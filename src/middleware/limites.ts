/**
 * Protección contra fuerza bruta (express-rate-limit).
 *
 * Sólo cuentan los intentos que terminan en error (`skipSuccessfulRequests`).
 * El contador sube al LLEGAR la petición, así que lanzar muchos intentos en
 * paralelo tampoco esquiva el límite.
 *
 *  - Por IP: frena a un origen que prueba muchas cuentas.
 *  - Por cuenta: frena los intentos contra un usuario aunque cambie la IP. Se
 *    aplica igual si la cuenta no existe, para no revelar cuáles existen.
 *
 * Costo asumido: quien conozca un nombre de usuario puede bloquearlo 15
 * minutos fallando a propósito. Los contadores viven en memoria.
 */

import rateLimit from 'express-rate-limit';

const VENTANA = 15 * 60 * 1000;

export const MAX_FALLOS_POR_IP = 20;
export const MAX_FALLOS_POR_CUENTA = 5;

const comunes = {
  windowMs: VENTANA,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7' as const,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Probá de nuevo en unos minutos.' },
};

export const limiteLoginPorIp = rateLimit({
  ...comunes,
  limit: MAX_FALLOS_POR_IP,
});

export const limiteLoginPorCuenta = rateLimit({
  ...comunes,
  limit: MAX_FALLOS_POR_CUENTA,
  keyGenerator: (req) => {
    const username: unknown = req.body?.username;
    return typeof username === 'string' ? username.trim().toLowerCase().slice(0, 64) : '';
  },
});

/** Intentos de adivinar la contraseña actual desde una sesión abierta. */
export const limiteCambioPassword = rateLimit({
  ...comunes,
  limit: 5,
  // Va después de requiereSesion: siempre hay un usuario.
  keyGenerator: (req) => String(req.usuario!.id),
});