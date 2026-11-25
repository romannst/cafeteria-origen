/** Roles, escalada de privilegios, cambio de contraseña e IDOR (Integrante 4). */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import * as db from '../src/db';
import {
  Agente,
  MARCA_PRUEBA,
  agente,
  crearUsuarioDePrueba,
  deleteConToken,
  limpiarDatosDePrueba,
  login,
  patchConToken,
  postConToken,
  prepararBase,
  productoPorNombre,
  putConToken,
} from './helpers';
import type { Pedido, Rol } from '../src/tipos';

const CLAVE = 'Sec_Clave_2024!';
const NUEVA = 'Otra_Clave_2025!';

async function entrar(username: string, rol: Rol): Promise<{ http: Agente; id: number }> {
  const { id } = await crearUsuarioDePrueba(username, CLAVE, rol);
  const http = agente();
  assert.equal((await login(http, username, CLAVE)).status, 200);
  return { http, id: id! };
}

const rolDe = async (id: number) =>
  (await db.query('SELECT rol FROM usuarios WHERE id = $1', [id])).rows[0].rol as string;

describe('Permisos', () => {
  before(prepararBase);
  after(async () => {
    delete process.env.ACCESO_ESTRICTO;
    await limpiarDatosDePrueba();
  });

  it('sólo un admin usa el panel', async () => {
    for (const rol of ['cliente', 'mozo', 'barista'] as const) {
      const { http, id } = await entrar(`sec_p_${rol}`, rol);
      assert.equal((await http.get('/api/admin/usuarios')).status, 403);
      assert.equal((await putConToken(http, `/api/admin/usuarios/${id}`, { rol: 'admin' })).status, 403);
      assert.equal((await postConToken(http, '/api/admin/probar-conexion', {})).status, 403);
      assert.equal(await rolDe(id), rol);
    }
    assert.equal((await agente().get('/api/admin/usuarios')).status, 401);
  });

  it('el admin no recibe hashes, valida los cambios y no cambia su propio rol', async () => {
    const admin = await entrar('sec_p_admin', 'admin');
    const otro = await entrar('sec_p_otro', 'cliente');
    const lista = await admin.http.get('/api/admin/usuarios');
    assert.equal(lista.status, 200);
    assert.doesNotMatch(JSON.stringify(lista.body), /password|\$2[aby]\$/);

    const url = `/api/admin/usuarios/${otro.id}`;
    for (const cambio of [{}, { rol: 'root' }, { password: 'corta' }, { username: 'a b' }, { id: 1 }]) {
      assert.equal((await putConToken(admin.http, url, cambio)).status, 400, JSON.stringify(cambio));
    }
    assert.equal((await putConToken(admin.http, url, { username: 'sec_p_admin' })).status, 409);
    const propio = `/api/admin/usuarios/${admin.id}`;
    assert.equal((await putConToken(admin.http, propio, { rol: 'cliente' })).status, 403);
    assert.equal((await putConToken(admin.http, propio, { password: NUEVA })).status, 403);
    assert.equal(await rolDe(admin.id), 'admin');

    const cambio = await putConToken(admin.http, url, { rol: 'barista', password: NUEVA });
    assert.equal(cambio.status, 200);
    assert.equal(cambio.body.password, undefined);
    // La sesión anterior del usuario modificado ya no vale.
    assert.equal((await otro.http.get('/api/auth/yo')).status, 401);
    assert.equal((await login(agente(), 'sec_p_otro', NUEVA)).status, 200);
  });

  it('cambiar la contraseña exige la actual y cierra las otras sesiones', async () => {
    const { http } = await entrar('sec_p_clave', 'mozo');
    const otra = agente();
    await login(otra, 'sec_p_clave', CLAVE);
    const url = '/api/admin/cambiar-contrasena';

    assert.equal((await postConToken(http, url, { nueva: NUEVA })).status, 400);
    assert.equal((await postConToken(http, url, { actual: 'mala', nueva: NUEVA })).status, 403);
    assert.equal((await postConToken(http, url, { actual: CLAVE, nueva: 'corta' })).status, 400);

    const res = await postConToken(http, url, { actual: CLAVE, nueva: NUEVA });
    assert.equal(res.status, 200);
    assert.doesNotMatch(JSON.stringify(res.body), /password|\$2[aby]\$/);
    assert.equal((await http.get('/api/auth/yo')).status, 200);
    assert.equal((await otra.get('/api/auth/yo')).status, 401);
    assert.equal((await login(agente(), 'sec_p_clave', CLAVE)).status, 401);
    assert.equal((await login(agente(), 'sec_p_clave', NUEVA)).status, 200);
  });

  it('borrar reseñas exige rol admin', async () => {
    const { rows } = await db.query(
      'INSERT INTO comentarios (autor, texto, calificacion) VALUES ($1, $2, 5) RETURNING id',
      [MARCA_PRUEBA, 'reseña de prueba']
    );
    const url = `/api/comentarios/${rows[0].id}`;
    assert.equal((await deleteConToken(agente(), url)).status, 401);
    const cliente = await entrar('sec_p_res_c', 'cliente');
    assert.equal((await deleteConToken(cliente.http, url)).status, 403);
    const admin = await entrar('sec_p_res_a', 'admin');
    assert.equal((await deleteConToken(admin.http, url)).status, 200);
  });

  it('con acceso estricto impide ver y modificar pedidos ajenos (IDOR)', async () => {
    process.env.ACCESO_ESTRICTO = 'true';
    const ana = await entrar('sec_p_ana', 'cliente');
    const beto = await entrar('sec_p_beto', 'cliente');
    const mozo = await entrar('sec_p_sala', 'mozo');
    const admin = await entrar('sec_p_jefa', 'admin');
    const { id: productoId } = await productoPorNombre('Muffin de chocolate');

    const creado = await postConToken(ana.http, '/api/pedidos', {
      mesa: '4', cliente: MARCA_PRUEBA, items: [{ productoId, cantidad: 1 }],
      // El dueño sale de la sesión: este campo se ignora.
      usuarioId: beto.id, usuario_id: beto.id,
    });
    assert.equal(creado.status, 201);
    assert.equal(creado.body.usuario_id, ana.id);
    const url = `/api/pedidos/${creado.body.id}`;
    const ids = async (http: Agente, ruta = '/api/pedidos') =>
      (await http.get(ruta)).body.pedidos.map((p: Pedido) => p.id);

    assert.equal((await agente().get(url)).status, 401);
    assert.equal((await agente().get('/api/pedidos')).status, 401);
    assert.equal((await ana.http.get(url)).status, 200);
    assert.equal((await beto.http.get(url)).status, 404);
    assert.deepEqual(await ids(ana.http), [creado.body.id]);
    assert.deepEqual(await ids(beto.http), []);
    assert.deepEqual(await ids(beto.http, "/api/pedidos?mesa=' OR '1'='1"), []);
    assert.equal((await mozo.http.get(url)).status, 200);
    assert.ok((await ids(mozo.http)).includes(creado.body.id));

    const estado = { estado: 'listo' };
    assert.equal((await patchConToken(agente(), `${url}/estado`, estado)).status, 401);
    assert.equal((await patchConToken(ana.http, `${url}/estado`, estado)).status, 403);
    assert.equal((await patchConToken(mozo.http, `${url}/estado`, estado)).status, 200);

    assert.equal((await agente().get('/api/reportes/facturacion')).status, 401);
    assert.equal((await mozo.http.get('/api/reportes/facturacion')).status, 403);
    assert.equal((await admin.http.get('/api/reportes/facturacion')).status, 200);
  });
});
