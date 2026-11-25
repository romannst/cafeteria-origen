import express from 'express';
import * as comentarios from '../services/comentarios.service';
import { comentarioValido } from '../validacion';
import { requiereSesion, requiereRol, ROLES_ADMIN } from '../middleware/auth';

const router = express.Router();

/**
 * GET /api/comentarios — reseñas públicas de la cafetería.
 * El sitio las pinta con innerHTML: por eso son un vector de XSS almacenado.
 */
router.get('/', async (req, res, next) => {
  try {
    res.json({ comentarios: await comentarios.listar() });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/comentarios
 *
 * Token anti-CSRF global y validación de longitud/rango en el servidor.
 * La salida se muestra como texto en el frontend (corrección XSS).
 */
router.post('/', async (req, res, next) => {
  try {
    const texto = req.body?.texto;
    if (typeof texto !== 'string' || texto.length > 280 || !comentarioValido(req.body)) {
      return res.status(400).json({ error: 'Datos de reseña inválidos.' });
    }
    const { autor, calificacion } = req.body || {};
    const comentario = await comentarios.crear({
      autor,
      texto,
      calificacion,
    });
    res.status(201).json(comentario);
  } catch (err) {
    next(err);
  }
});

/** DELETE /api/comentarios/:id — sólo administradores. */
router.delete('/:id', requiereSesion, requiereRol(...ROLES_ADMIN), async (req, res, next) => {
  try {
    const comentario = await comentarios.eliminar(req.params.id);
    if (!comentario) {
      return res.status(404).json({ error: 'Comentario no encontrado.' });
    }
    res.json(comentario);
  } catch (err) {
    next(err);
  }
});

export default router;
