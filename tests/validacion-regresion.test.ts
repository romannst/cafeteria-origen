import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import * as db from '../src/db';
import { agente, postConToken, prepararBase, productoPorNombre } from './helpers';

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
});
