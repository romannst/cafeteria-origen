/**
 * Gestión de sesiones.
 *
 * -----------------------------------------------------------------------------
 * CORREGIDO — Gestión de sesiones insegura (Autenticación insegura)
 * -----------------------------------------------------------------------------
 * 1. Identificador aleatorio: 32 bytes de crypto.randomBytes (256 bits), no
 *    se puede adivinar ni recorrer.
 * 2. Cookie con HttpOnly (JavaScript no la lee), SameSite=Lax (defensa
 *    complementaria contra CSRF) y Secure en producción (sólo viaja por
 *    HTTPS; la práctica local usa HTTP).
 * 3. Vencimiento doble: por inactividad (30 min) y absoluto (8 h).
 * 4. Al iniciar sesión se descarta el identificador anterior y se genera uno
 *    nuevo (contra la fijación de sesión). Sólo valen los ids creados acá.
 * 5. El cierre de sesión borra la sesión del servidor, no sólo la cookie.
 *
 * Limitación conocida: el almacén es un Map en memoria. Al reiniciar la app se
 * cierran todas las sesiones y no sirve con varias instancias; en un proyecto
 * real se usaría un almacén compartido (Redis o la base de datos).
 * -----------------------------------------------------------------------------
 */

import { randomBytes } from 'crypto';
import type { CookieOptions, Request, Response } from 'express';

import type { Sesion, UsuarioSesion } from '../tipos';


export const TIEMPO_INACTIVIDAD = 30 * 60 * 1000;
export const MAX_VIDA = 8 * 60 * 60 * 1000;

const COOKIE = 'sid';

export const sesiones = new Map<string, Sesion>();

/** Opciones comunes: para borrar la cookie hay que usar las mismas. */
function opcionesCookie(): CookieOptions {
  return {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  };
}

/** Lee las cookies de la petición (parser mínimo, sin dependencias). */
export function leerCookies(req: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  const header = req.headers.cookie;
  if (!header) return cookies;
  for (const parte of header.split(';')) {
    const separador = parte.indexOf('=');
    if (separador < 0) continue;
    const nombre = parte.slice(0, separador).trim();
    const valor = parte.slice(separador + 1).trim();
    if (!nombre) continue;
    try {
      cookies[nombre] = decodeURIComponent(valor);
    } catch {
      // Una cookie mal codificada (por ejemplo "%") se ignora, sin error 500.
    }
  }
  return cookies;
}

/** Crea una sesión nueva para el usuario y setea la cookie. */
export function crearSesion(req: Request, res: Response, usuario: UsuarioSesion): string {
  // Regeneración: la sesión que traía la petición deja de existir.
  destruirSesion(req);

  const id = randomBytes(32).toString('hex');
  const ahora = Date.now();
  sesiones.set(id, {
    // Copia explícita: nunca se guarda el hash ni otros campos del usuario.
    usuario: {
      id: usuario.id,
      username: usuario.username,
      rol: usuario.rol,
      nombre: usuario.nombre,
    },
    creadaEn: ahora,
    expiraEn: ahora + TIEMPO_INACTIVIDAD,
  });

  res.cookie(COOKIE, id, { ...opcionesCookie(), maxAge: MAX_VIDA });

  return id;
}

/**
 * Devuelve la sesión vigente de la petición. Una sesión vencida se elimina; una
 * vigente renueva su plazo de inactividad sin pasar la vida máxima.
 */
export function obtenerSesion(req: Request): Sesion | null {
  const id = leerCookies(req)[COOKIE];
  if (!id) return null;
  const sesion = sesiones.get(id);
  if (!sesion) return null;

  const ahora = Date.now();
  if (ahora >= sesion.expiraEn) {
    sesiones.delete(id);
    return null;
  }
  sesion.expiraEn = Math.min(ahora + TIEMPO_INACTIVIDAD, sesion.creadaEn + MAX_VIDA);
  return sesion;
}

/** Cierra la sesión en el servidor. */
export function destruirSesion(req: Request): void {
  const id = leerCookies(req)[COOKIE];
  if (id) sesiones.delete(id);
}

/** Pide al navegador que borre la cookie de sesión. */
export function borrarCookieSesion(res: Response): void {
  res.clearCookie(COOKIE, opcionesCookie());
}

/**
 * Cierra todas las sesiones de un usuario. Se usa cuando cambian su rol o su
 * contraseña, para que una sesión abierta no conserve los datos anteriores.
 */
export function destruirSesionesDeUsuario(usuarioId: number): void {
  for (const [id, sesion] of sesiones) {
    if (sesion.usuario.id === usuarioId) sesiones.delete(id);
  }
}

// Las sesiones abandonadas se eliminan periódicamente para no acumular memoria.
// unref(): este temporizador no impide que el proceso termine.
setInterval(() => {
  const ahora = Date.now();
  for (const [id, sesion] of sesiones) {
    if (ahora >= sesion.expiraEn) sesiones.delete(id);
  }
}, 5 * 60 * 1000).unref();