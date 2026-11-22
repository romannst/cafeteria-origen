import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import app from '../src/app';

describe('CSRF: visitantes y operaciones del panel', () => {
  it('rechaza escrituras sin token y con token de otro visitante', async () => {
    const visitante = request.agent(app);
    const ajeno = request.agent(app);
    const token = (await visitante.get('/api/csrf-token')).body.token;
    const otroToken = (await ajeno.get('/api/csrf-token')).body.token;
    assert.match(token, /^[a-f0-9]{64}$/);
    assert.notEqual(token, otroToken);

    const cuerpo = { mesa: '1', cliente: 'Prueba', items: [] };
    assert.equal((await visitante.post('/api/pedidos').send(cuerpo)).status, 403);
    assert.equal(
      (await visitante.post('/api/pedidos').set('X-CSRF-Token', otroToken).send(cuerpo)).status,
      403
    );
    assert.equal(
      (await visitante.post('/api/pedidos')
        .set('X-CSRF-Token', token).set('Origin', 'http://sitio-ajeno.test').send(cuerpo)).status,
      403
    );
    // El cuerpo vacío no debe alcanzar el servicio; logout no requiere DB.
    assert.equal(
      (await visitante.post('/api/auth/logout').set('X-CSRF-Token', token).send({})).status,
      200
    );
  });

  it('rechaza el cambio de contraseña sin token antes de llegar a la ruta', async () => {
    const res = await request(app).post('/api/admin/cambiar-contrasena').send({ nueva: 'ficticia' });
    assert.equal(res.status, 403);
    assert.match(res.body.error, /CSRF/);
  });

  it('rechaza un login desde un origen ajeno antes de autenticar', async () => {
    const res = await request(app).post('/api/auth/login')
      .set('Origin', 'http://sitio-ajeno.test')
      .send({ username: 'ficticio', password: 'ficticia' });
    assert.equal(res.status, 403);
  });

  it('exige token en login y rechaza tokens malformados sin error interno', async () => {
    const http = request.agent(app);
    const token = (await http.get('/api/csrf-token')).body.token;
    for (const recibido of [undefined, 'é'.repeat(64), 'a'.repeat(63), 'z'.repeat(64)]) {
      const res = await http.post('/api/auth/login').send({ _csrf: recibido });
      assert.equal(res.status, 403);
      assert.match(res.body.error, /CSRF/);
    }
    // Sin credenciales, un token correcto llega a la validación del login.
    assert.equal((await http.post('/api/auth/login')
      .set('X-CSRF-Token', token).send({})).status, 400);
  });

  it('el formulario de login del panel solicita y envía el token', async () => {
    const nodos = new Map<string, any>();
    const nodo = (selector: string) => {
      if (!nodos.has(selector)) nodos.set(selector, {
        value: 'dato-ficticio',
        addEventListener(this: any, evento: string, callback: unknown) { this[evento] = callback; },
      });
      return nodos.get(selector);
    };
    const llamadas: string[] = [];
    let terminar!: (config: any) => void;
    const envio = new Promise<any>(resolve => { terminar = resolve; });
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../src/public/js/admin.js'), 'utf8'), {
      document: { readyState: 'complete', querySelector: nodo },
      window: { location: { search: '' } },
      URLSearchParams,
      fetch: async (url: string, config: any) => {
        llamadas.push(url);
        if (url === '/api/auth/login') terminar(config);
        return {
          ok: url === '/api/csrf-token',
          status: url === '/api/csrf-token' ? 200 : 401,
          json: async () => url === '/api/csrf-token' ? { token: 'token-de-prueba' } : {},
        };
      },
    });
    nodo('#form-login').submit({ preventDefault() {} });
    const config = await envio;
    assert.equal(config.headers['X-CSRF-Token'], 'token-de-prueba');
    assert.equal(config.method, 'POST');
    assert.ok(llamadas.indexOf('/api/csrf-token') < llamadas.indexOf('/api/auth/login'));
  });
});
