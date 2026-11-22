import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import * as db from '../src/db';
import { agente, postConToken, patchConToken, prepararBase, productoPorNombre } from './helpers';

const marca = `__roman_validacion_${Date.now()}__`;

describe('Validación con token CSRF válido', () => {
  let productoId: number;
  before(async () => {
    await prepararBase();
    productoId = (await productoPorNombre('Muffin de chocolate')).id;
  });
  after(async () => {
    // Se borran sólo los registros creados por esta prueba, no la evidencia.
    await db.query('DELETE FROM pedidos WHERE cliente = $1', [marca]);
    await db.query('DELETE FROM comentarios WHERE autor = $1', [marca]);
  });

  it('rechaza cantidades inválidas sin escribir pedidos', async () => {
    const http = agente();
    for (const cantidad of [-5, 'abc', 0, 1.5, 101]) {
      const res = await postConToken(http, '/api/pedidos', {
        mesa: '6', cliente: marca,
        items: [{ productoId, cantidad }],
      });
      assert.equal(res.status, 400, `cantidad ${cantidad}`);
    }
    const inexistente = await postConToken(http, '/api/pedidos', {
      mesa: '6', cliente: marca,
      items: [{ productoId: 2147483647, cantidad: 1 }],
    });
    assert.equal(inexistente.status, 400);
    assert.ok(!JSON.stringify(inexistente.body).includes('stack'));
    const { rows } = await db.query('SELECT id FROM pedidos WHERE cliente = $1', [marca]);
    assert.equal(rows.length, 0);
  });

  it('rechaza reseñas extensas y acepta una reseña normal', async () => {
    const http = agente();
    const larga = await postConToken(http, '/api/comentarios', {
      autor: marca, texto: 'A'.repeat(50000), calificacion: 4,
    });
    assert.equal(larga.status, 400);
    const normal = await postConToken(http, '/api/comentarios', {
      autor: marca, texto: 'Muy buen café', calificacion: 4,
    });
    assert.equal(normal.status, 201);
  });

  it('acepta un pedido legítimo con token', async () => {
    const res = await postConToken(agente(), '/api/pedidos', {
      mesa: '6', cliente: marca, items: [{ productoId, cantidad: 1 }],
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.items[0].cantidad, 1);
  });

  it('rechaza IDs de ruta inválidos antes de consultar la base', async () => {
    const http = agente();
    for (const id of ['abc', '0', '-1', '1.5', '1e2', '2147483648', '9007199254740993']) {
      assert.equal((await http.get(`/api/pedidos/${id}`)).status, 400, id);
      assert.equal((await patchConToken(http, `/api/pedidos/${id}/estado`, {
        estado: 'listo',
      })).status, 400, id);
      assert.equal((await http.get(`/api/productos/${id}`)).status, 404, id);
    }
    assert.equal((await http.get('/api/pedidos/2147483647')).status, 404);
  });

  it('rechaza campos fuera de límites sin persistir pedidos', async () => {
    const http = agente();
    const valido = { mesa: '6', cliente: marca, items: [{ productoId, cantidad: 1 }] };
    const casos = [
      { mesa: 'abc' }, { mesa: '1'.repeat(11) }, { mesa: 6 },
      { cliente: ' ' }, { cliente: 'x'.repeat(41) }, { cliente: 7 },
      { items: [] }, { items: Array(21).fill({ productoId, cantidad: 1 }) },
      ...[0, -1, 'abc', 1.5, 2147483648, true].map(id => ({
        items: [{ productoId: id, cantidad: 1 }],
      })),
    ];
    const antes = await db.query('SELECT count(*) FROM pedidos');
    for (const cambio of casos) {
      const res = await postConToken(http, '/api/pedidos', { ...valido, ...cambio });
      assert.equal(res.status, 400, JSON.stringify(cambio));
    }
    const despues = await db.query('SELECT count(*) FROM pedidos');
    assert.equal(despues.rows[0].count, antes.rows[0].count);
  });

  it('valida longitudes, tipos y rango de reseñas', async () => {
    const http = agente();
    const valido = { autor: marca, texto: 'Texto válido', calificacion: 5 };
    for (const cambio of [
      { autor: ' ' }, { autor: 'x'.repeat(41) }, { texto: 'ab' },
      { texto: 'x'.repeat(281) }, { texto: 123 }, { calificacion: 0 },
      { calificacion: 6 }, { calificacion: 2.5 }, { calificacion: '5' },
    ]) {
      assert.equal((await postConToken(http, '/api/comentarios', {
        ...valido, ...cambio,
      })).status, 400, JSON.stringify(cambio));
    }
    for (const texto of ['abc', 'x'.repeat(280)]) {
      assert.equal((await postConToken(http, '/api/comentarios', {
        ...valido, texto,
      })).status, 201);
    }
  });

  it('rechaza estados inválidos sin alterar el pedido y acepta la lista permitida', async () => {
    const http = agente();
    const creado = await postConToken(http, '/api/pedidos', {
      mesa: '6', cliente: marca, items: [{ productoId, cantidad: 100 }],
    });
    assert.equal(creado.status, 201);
    const url = `/api/pedidos/${creado.body.id}`;
    for (const estado of ['desconocido', '', 1, null, ['listo']]) {
      assert.equal((await patchConToken(http, `${url}/estado`, { estado })).status, 400);
      assert.equal((await http.get(url)).body.estado, 'abierto');
    }
    for (const estado of ['preparando', 'listo', 'entregado', 'cancelado', 'abierto']) {
      const res = await patchConToken(http, `${url}/estado`, { estado });
      assert.equal(res.status, 200);
      assert.equal(res.body.estado, estado);
    }
  });
});
