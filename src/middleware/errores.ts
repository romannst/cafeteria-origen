/**
 * Manejo de errores.
 *
 * FALLA — Exposición de información sensible:
 * la respuesta al cliente incluye el mensaje de error original y el stack
 * trace completo, que revela rutas internas del servidor, nombres de tablas,
 * fragmentos de consultas SQL y versiones de librerías.
 *
 * Corrección: responder con un mensaje genérico ("Error interno") y registrar
 * el detalle real en el log del servidor.
 */

import type { NextFunction, Request, Response } from 'express';

import type { ErrorHttp } from '../tipos';

export function rutaNoEncontrada(req: Request, res: Response): void {
  res.status(404).json({ error: `Ruta no encontrada: ${req.originalUrl}` });
}

// Express reconoce al manejador de errores por sus CUATRO parámetros: `next`
// tiene que estar aunque no se use.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function manejadorErrores(
  err: ErrorHttp,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const status = typeof err.status === 'number' ? err.status : 500;

 
  console.error('[error]', {
    status,
    metodo: req.method,
    ruta: req.originalUrl,
    message: err.message,
    stack: err.stack,
  });

  if (status >= 500) {
    res.status(status).json({ error: 'Error interno' });
    return;
  }

  const mensajeCliente =
    err.message && !/select|insert|update|delete|from|where|pg_|relation|column|sql/i.test(err.message)
      ? err.message
      : 'Solicitud inválida';

  res.status(status).json({ error: mensajeCliente });
}
