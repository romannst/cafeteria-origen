import express from 'express';
import * as reportes from '../services/reportes.service';
import { requiereRol, requiereSesion, soloEstricto, ROLES_ADMIN } from '../middleware/auth';

const router = express.Router();

// La facturación es información del negocio: con acceso estricto, sólo admin.
router.use(soloEstricto(requiereSesion), soloEstricto(requiereRol(...ROLES_ADMIN)));

/** GET /api/reportes/facturacion — cuánto se facturó. */
router.get('/facturacion', async (req, res, next) => {
  try {
    res.json(await reportes.facturacion());
  } catch (err) {
    next(err);
  }
});

/** GET /api/reportes/cantidad-vendida — unidades por tipo de producto. */
router.get('/cantidad-vendida', async (req, res, next) => {
  try {
    res.json({ cantidadVendida: await reportes.cantidadVendidaPorTipo() });
  } catch (err) {
    next(err);
  }
});

/** GET /api/reportes/mas-vendido — producto más vendido. */
router.get('/mas-vendido', async (req, res, next) => {
  try {
    res.json({ producto: await reportes.masVendido() });
  } catch (err) {
    next(err);
  }
});

/** GET /api/reportes/ticket-promedio */
router.get('/ticket-promedio', async (req, res, next) => {
  try {
    res.json(await reportes.ticketPromedio());
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/reportes/ventas-por-variedad?variedad=
 *
 * FALLA — Inyección SQL: el origen se concatena en la consulta.
 */
router.get('/ventas-por-variedad', async (req, res, next) => {
  try {
    const variedad = (req.query.variedad as string | undefined) || '';
    res.json({ ventas: await reportes.ventasPorVariedad(variedad) });
  } catch (err) {
    next(err);
  }
});

export default router;
