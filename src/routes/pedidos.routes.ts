import express from 'express';
import * as pedidos from '../services/pedidos.service';
import { pedidoValido, estadoValido, idValido } from '../validacion';

const router = express.Router();

router.param('id', (req, res, next, id) => {
  if (!idValido(id)) return res.status(400).json({ error: 'ID de pedido inválido.' });
  next();
});

/**
 * POST /api/pedidos
 * Crea un pedido y devuelve su total calculado.
 *
 * Token CSRF: aplicado en src/app.ts. Tipo, rango y longitud de las entradas
 * se validan antes de insertar el pedido. La cookie `sid` depende del bloque
 * de sesiones.
 * FALLA pendiente de otro bloque:
 *  - No requiere autenticación ni rol.
 */
router.post('/', async (req, res, next) => {
  try {
    if (!pedidoValido(req.body)) {
      return res.status(400).json({ error: 'Datos del pedido inválidos.' });
    }
    const { mesa, cliente, items } = req.body || {};
    const pedido = await pedidos.crear({
      mesa, cliente,
      items: items.map((item: { productoId: number | string; cantidad: number | string }) => ({
        productoId: Number(item.productoId),
        cantidad: Number(item.cantidad),
      })),
    });
    res.status(201).json(pedido);
  } catch (err) {
    if ((err as { status?: number }).status === 400) {
      return res.status(400).json({ error: 'Producto no encontrado.' });
    }
    next(err);
  }
});

/**
 * GET /api/pedidos?mesa=
 * Lista los pedidos de todas las mesas.
 *
 * FALLA — Inyección SQL en el filtro de mesa.
 * FALLA — Autorización: cualquier visitante puede ver los pedidos de TODAS
 * las mesas (los datos de los clientes de los demás).
 */
router.get('/', async (req, res, next) => {
  try {
    res.json({ pedidos: await pedidos.listar(req.query.mesa as string | undefined) });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/pedidos/:id
 * FALLA — IDOR: no se verifica que el pedido pertenezca al usuario que pregunta.
 */
router.get('/:id', async (req, res, next) => {
  try {
    const pedido = await pedidos.obtenerConItems(req.params.id);
    if (!pedido) {
      return res.status(404).json({ error: 'Pedido no encontrado.' });
    }
    res.json(pedido);
  } catch (err) {
    next(err);
  }
});

/** PATCH /api/pedidos/:id/estado */
router.patch('/:id/estado', async (req, res, next) => {
  try {
    const { estado } = req.body || {};
    if (!estadoValido(estado)) {
      return res.status(400).json({ error: 'Estado de pedido inválido.' });
    }
    const pedido = await pedidos.cambiarEstado(req.params.id, estado);
    if (!pedido) {
      return res.status(404).json({ error: 'Pedido no encontrado.' });
    }
    res.json(pedido);
  } catch (err) {
    next(err);
  }
});

export default router;
