import { randomBytes, timingSafeEqual } from 'crypto';
import type { Request, RequestHandler, Response } from 'express';
import { leerCookies, obtenerSesion } from './sesion';

// Identificador anónimo y token se conservan sólo en el servidor. Al iniciar
// sesión, la clave pasa a ser el identificador de esa sesión.
const tokens = new Map<string, string>();
const COOKIE = 'csrf_visitante';

function clave(req: Request, res?: Response): string | null {
  const sid = leerCookies(req).sid;
  if (sid && obtenerSesion(req)) return `sesion:${sid}`;
  let visitante = leerCookies(req)[COOKIE];
  if (!visitante && res) {
    visitante = randomBytes(32).toString('hex');
    res.cookie(COOKIE, visitante, { httpOnly: true, sameSite: 'lax', path: '/' });
  }
  return visitante && /^[a-f0-9]{64}$/.test(visitante) ? `visitante:${visitante}` : null;
}

export const obtenerToken: RequestHandler = (req, res) => {
  const id = clave(req, res);
  if (!id) return res.status(403).json({ error: 'No se pudo crear el token CSRF.' });
  if (!tokens.has(id)) tokens.set(id, randomBytes(32).toString('hex'));
  res.setHeader('Cache-Control', 'no-store');
  res.json({ token: tokens.get(id) });
};

export const protegerCsrf: RequestHandler = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // Si el navegador informa el origen, no aceptamos formularios de otro
  // origen aunque consiguieran enviar una cookie.
  const origen = req.get('Origin') || req.get('Referer');
  if (origen) {
    try {
      if (new URL(origen).origin !== `${req.protocol}://${req.get('host')}`) {
        return res.status(403).json({ error: 'Origen de petición no permitido.' });
      }
    } catch {
      return res.status(403).json({ error: 'Origen de petición no permitido.' });
    }
  }

  // Login: se exige el origen correcto cuando está presente, pero se conserva
  // la compatibilidad con los clientes que todavía inician sesión sin token.
  // Coordinar token obligatorio en login con las pruebas del bloque de auth.
  if (req.path === '/auth/login') return next();

  const id = clave(req);
  const esperado = id && tokens.get(id);
  const recibido = req.get('X-CSRF-Token') || req.body?._csrf || req.query._csrf;
  if (
    typeof esperado !== 'string' ||
    typeof recibido !== 'string' ||
    recibido.length !== esperado.length ||
    !timingSafeEqual(Buffer.from(recibido), Buffer.from(esperado))
  ) {
    return res.status(403).json({ error: 'Token CSRF inválido o ausente.' });
  }
  next();
};
