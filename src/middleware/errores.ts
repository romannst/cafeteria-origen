/**
 * Manejo de errores.
 *
 * CORREGIDO — Exposición de información sensible y XSS reflejado: el cliente
 * recibe mensajes fijos. No se devuelve el stack trace, el mensaje interno
 * (que puede nombrar tablas, rutas o consultas) ni la URL pedida. El detalle
 * real queda en el log del servidor.
 */

import type { NextFunction, Request, Response } from 'express';

import type { ErrorHttp } from '../tipos';

/** Mensajes para los errores atribuibles a la petición. */
const MENSAJES: Record<number, string> = {
  400: 'La solicitud no es válida.',
  413: 'La solicitud es demasiado grande.',
  415: 'El formato enviado no está admitido.',
};

export function rutaNoEncontrada(req: Request, res: Response): void {
  res.status(404).json({ error: 'Ruta no encontrada.' });
}

// Express reconoce al manejador de errores por sus CUATRO parámetros: `next`
// tiene que estar aunque no siempre se use.
export function manejadorErrores(err: ErrorHttp, req: Request, res: Response, next: NextFunction): void {
  const pedido = err.status ?? 500;
  const estado = pedido >= 400 && pedido < 500 ? pedido : 500;

  // El stack va sólo al log. En errores del cliente no se registra el mensaje,
  // porque puede repetir parte del cuerpo enviado (incluida una contraseña).
  console.error('[error]', estado, req.method, req.path, estado === 500 ? err.stack : err.name);

  // Si la respuesta ya empezó a enviarse, Express cierra la conexión.
  if (res.headersSent) return next(err);

  const mensaje = estado === 500 ? 'Error interno del servidor.' : MENSAJES[estado] ?? MENSAJES[400];
  res.status(estado).json({ error: mensaje });
}