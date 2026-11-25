import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { obtenerSesion } from './sesion';
import type { Rol } from '../tipos';

/**
 * Middlewares de autenticación y autorización.
 *
 * Autenticación = saber quién es (401 si no se sabe).
 * Autorización  = saber si puede hacerlo (403 si no puede).
 *
 * Matriz de permisos:
 *
 *   Operación                          visitante  cliente   barista/mozo  admin
 *   Ver catálogo y reseñas, pedir          sí        sí          sí         sí
 *   Cambiar la propia contraseña           no        sí          sí         sí
 *   Panel /api/admin (resto)               no        no          no         sí
 *   Borrar reseñas                         no        no          no         sí
 *   Ver pedidos (*)                        no      propios      todos      todos
 *   Cambiar estado de un pedido (*)        no        no          sí         sí
 *   Ver reportes de facturación (*)        no        no          no         sí
 *
 *   (*) Sólo con el acceso estricto activo: ver accesoEstricto().
 */

/** Roles del personal que trabaja con los pedidos de todas las mesas. */
export const ROLES_PERSONAL: Rol[] = ['admin', 'barista', 'mozo'];

/** Roles que administran el sistema. */
export const ROLES_ADMIN: Rol[] = ['admin'];

/**
 * ¿Se exigen permisos sobre pedidos y reportes?
 *
 * Los tests funcionales originales consultan pedidos y reportes, y cambian
 * estados, SIN iniciar sesión. Para no romperlos, fuera de producción ese
 * control está apagado salvo que se defina ACCESO_ESTRICTO=true. En
 * producción está siempre activo.
 */
export function accesoEstricto(): boolean {
  return process.env.NODE_ENV === 'production' || process.env.ACCESO_ESTRICTO === 'true';
}

/** Exige que haya una sesión válida. */
export function requiereSesion(req: Request, res: Response, next: NextFunction) {
  const sesion = obtenerSesion(req);
  if (!sesion) {
    return res.status(401).json({ error: 'Necesitás iniciar sesión.' });
  }
  req.usuario = sesion.usuario;
  req.sesion = sesion;
  next();
}

/** Exige que el usuario autenticado tenga uno de los roles indicados. */
export function requiereRol(...roles: Rol[]): RequestHandler {
  return (req, res, next) => {
    if (!req.usuario) {
      return res.status(401).json({ error: 'Necesitás iniciar sesión.' });
    }
    if (!roles.includes(req.usuario.rol)) {
      return res.status(403).json({ error: 'No tenés permisos para esta operación.' });
    }
    next();
  };
}

/** Aplica un control sólo cuando el acceso estricto está activo. */
export function soloEstricto(control: RequestHandler): RequestHandler {
  return (req, res, next) => (accesoEstricto() ? control(req, res, next) : next());
}
