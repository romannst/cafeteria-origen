/** Contraseñas, login, fuerza bruta y sesiones (Integrante 4). */
import assert from 'node:assert/strict';
import { after, before, describe, it, mock } from 'node:test';
import request from 'supertest';
import * as db from '../src/db';
import { migrarPasswordsEnClaro } from '../src/inicializar';
import { MAX_VIDA, TIEMPO_INACTIVIDAD, sesiones } from '../src/middleware/sesion';
import { MAX_FALLOS_POR_CUENTA } from '../src/middleware/limites';
import { esHash } from '../src/passwords';
import {
  agente,
  app,
  cookieCruda,
  crearUsuarioDePrueba,
  limpiarDatosDePrueba,
  login,
  prepararBase,
  tokenCsrf,
} from './helpers';

const CLAVE = 'Sec_Clave_2024!';
const sidDe = (res: request.Response) => /sid=([^;]+)/.exec(cookieCruda(res))![1];
const yo = (sid: string) => request(app).get('/api/auth/yo').set('Cookie', `sid=${sid}`);

describe('Contraseñas, login y sesiones', () => {
  before(prepararBase);
  after(limpiarDatosDePrueba);

  it('convierte a bcrypt una contraseña que estaba en texto plano', async () => {
    await db.query(
      "INSERT INTO usuarios (username, password, rol) VALUES ('sec_s_migra', $1, 'mozo')",
      [CLAVE]
    );
    await migrarPasswordsEnClaro();
    const leer = async () =>
      (await db.query("SELECT password FROM usuarios WHERE username = 'sec_s_migra'")).rows[0]
        .password as string;
    const hash = await leer();
    assert.ok(esHash(hash));
    // Una segunda pasada no vuelve a hashear el hash.
    await migrarPasswordsEnClaro();
    assert.equal(await leer(), hash);
    assert.equal((await login(agente(), 'sec_s_migra', CLAVE)).status, 200);
    // Conocer el hash no sirve para entrar.
    assert.equal((await login(agente(), 'sec_s_migra', hash)).status, 401);
  });

  it('rechaza tipos raros, bytes nulos y claves de más de 72 bytes sin error 500', async () => {
    const larga = 'a'.repeat(72);
    await crearUsuarioDePrueba('sec_s_larga', larga);
    // bcrypt truncaría el sufijo: tiene que rechazarse igual.
    assert.equal((await login(agente(), 'sec_s_larga', larga + 'extra')).status, 401);
    assert.equal((await login(agente(), 'sec_s_\0', 'x')).status, 401);
    const http = agente();
    const token = await tokenCsrf(http);
    for (const cuerpo of [
      { username: { a: 1 }, password: 'x' },
      { username: 'sec_s_larga', password: ['x'] },
    ]) {
      const res = await http.post('/api/auth/login').set('X-CSRF-Token', token!).send(cuerpo);
      assert.equal(res.status, 400);
    }
  });

  it('emite una cookie protegida y agrega Secure en producción', async () => {
    await crearUsuarioDePrueba('sec_s_cookie', CLAVE);
    const normal = cookieCruda(await login(agente(), 'sec_s_cookie', CLAVE));
    assert.match(normal, /^sid=[a-f0-9]{64};/);
    assert.match(normal, /HttpOnly/);
    assert.match(normal, /SameSite=Lax/);
    assert.match(normal, new RegExp(`Max-Age=${MAX_VIDA / 1000}`));
    assert.doesNotMatch(normal, /Secure/);

    const anterior = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      assert.match(cookieCruda(await login(agente(), 'sec_s_cookie', CLAVE)), /; Secure/);
    } finally {
      if (anterior === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = anterior;
    }
  });

  it('renueva el id al iniciar sesión e ignora ids elegidos por el cliente', async () => {
    await crearUsuarioDePrueba('sec_s_fija', CLAVE);
    const http = agente();
    const primero = sidDe(await login(http, 'sec_s_fija', CLAVE));
    const segundo = sidDe(await login(http, 'sec_s_fija', CLAVE));
    assert.notEqual(primero, segundo);
    assert.equal((await yo(primero)).status, 401);
    assert.equal((await yo(segundo)).status, 200);
    assert.equal((await yo('a'.repeat(64))).status, 401);
    assert.equal((await yo('%')).status, 401);
  });

  it('vence por inactividad', async () => {
    await crearUsuarioDePrueba('sec_s_idle', CLAVE);
    const sid = sidDe(await login(agente(), 'sec_s_idle', CLAVE));
    const inicio = Date.now();
    const reloj = mock.method(Date, 'now', () => inicio + TIEMPO_INACTIVIDAD + 1000);
    try {
      assert.equal((await yo(sid)).status, 401);
      assert.equal(sesiones.has(sid), false);
    } finally {
      reloj.mock.restore();
    }
  });

  it('vence a las 8 horas aunque haya actividad continua', async () => {
    await crearUsuarioDePrueba('sec_s_abs', CLAVE);
    const sid = sidDe(await login(agente(), 'sec_s_abs', CLAVE));
    const inicio = sesiones.get(sid)!.creadaEn;
    let ahora = inicio;
    const reloj = mock.method(Date, 'now', () => ahora);
    try {
      const paso = TIEMPO_INACTIVIDAD - 60_000;
      for (ahora = inicio + paso; ahora < inicio + MAX_VIDA; ahora += paso) {
        assert.equal((await yo(sid)).status, 200);
      }
      ahora = inicio + MAX_VIDA;
      assert.equal((await yo(sid)).status, 401);
    } finally {
      reloj.mock.restore();
    }
  });

  it('bloquea una cuenta tras varios fallos, exista o no', async () => {
    await crearUsuarioDePrueba('sec_s_bruta', CLAVE);
    for (const username of ['sec_s_bruta', 'sec_s_fantasma']) {
      for (let i = 0; i < MAX_FALLOS_POR_CUENTA; i++) {
        assert.equal((await login(agente(), username, 'mala')).status, 401);
      }
      const bloqueado = await login(agente(), username.toUpperCase(), CLAVE);
      assert.equal(bloqueado.status, 429);
      assert.match(bloqueado.body.error, /Demasiados intentos/);
    }
  });
});
