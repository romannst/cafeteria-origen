import express from 'express';
import * as pedidos from '../services/pedidos.service';
import { pedidoValido, estadoValido, idValido } from '../validacion';
import {
  accesoEstricto,
  requiereRol,
  requiereSesion,
  soloEstricto,
  ROLES_PERSONAL,
} from '../middleware/auth';
import { obtenerSesion } from '../middleware/sesion';

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
 * se validan antes de insertar el pedido.
 *
 * Es público a propósito: el cliente pide desde la mesa sin cuenta. Si hay
 * sesión, el pedido queda asociado a ese usuario.
 */
router.post('/', async (req, res, next) => {
  try {
    if (!pedidoValido(req.body)) {
      return res.status(400).json({ error: 'Datos del pedido inválidos.' });
    }
    const { mesa, cliente, items } = req.body || {};
    const pedido = await pedidos.crear({
      mesa, cliente,
      usuarioId: obtenerSesion(req)?.usuario.id ?? null,
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
 * Con acceso estricto: el personal ve todos los pedidos y un cliente sólo los
 * suyos. Sin él (compatibilidad con los tests funcionales) la lista es pública.
 *
 * La inyección SQL del filtro de mesa corresponde al bloque SQLi.
 */
router.get('/', soloEstricto(requiereSesion), async (req, res, next) => {
  try {
    const mesa = req.query.mesa as string | undefined;
    if (accesoEstricto() && !ROLES_PERSONAL.includes(req.usuario!.rol)) {
      const filtro = typeof mesa === 'string' ? mesa : undefined;
      return res.json({ pedidos: await pedidos.listarDeUsuario(req.usuario!.id, filtro) });
    }
    res.json({ pedidos: await pedidos.listar(mesa) });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/pedidos/:id
 * CORREGIDO (con acceso estricto) — IDOR: además de la sesión se comprueba que
 * el pedido sea del usuario que pregunta, salvo que sea personal. Un pedido
 * ajeno responde igual que uno inexistente (404), para no revelar que existe.
 */
router.get('/:id', soloEstricto(requiereSesion), async (req, res, next) => {
  try {
    const pedido = await pedidos.obtenerConItems(String(req.params.id));
    const ajeno =
      accesoEstricto() &&
      !ROLES_PERSONAL.includes(req.usuario!.rol) &&
      pedido?.usuario_id !== req.usuario!.id;
    if (!pedido || ajeno) {
      return res.status(404).json({ error: 'Pedido no encontrado.' });
    }
    res.json(pedido);
  } catch (err) {
    next(err);
  }
});

/** PATCH /api/pedidos/:id/estado */
router.patch(
  '/:id/estado',
  soloEstricto(requiereSesion),
  soloEstricto(requiereRol(...ROLES_PERSONAL)),
  async (req, res, next) => {
    try {
      const { estado } = req.body || {};
      if (!estadoValido(estado)) {
        return res.status(400).json({ error: 'Estado de pedido inválido.' });
      }
      const pedido = await pedidos.cambiarEstado(String(req.params.id), estado);
      if (!pedido) {
        return res.status(404).json({ error: 'Pedido no encontrado.' });
      }
      res.json(pedido);
    } catch (err) {
      next(err);
    }
  }
);

export default router;
