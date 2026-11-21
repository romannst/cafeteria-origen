import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';
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
});
