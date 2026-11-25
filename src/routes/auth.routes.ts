import express from 'express';
import * as usuarios from '../services/usuarios.service';
import {
  borrarCookieSesion,
  crearSesion,
  destruirSesion,
  obtenerSesion,
} from '../middleware/sesion';
import { limiteLoginPorCuenta, limiteLoginPorIp } from '../middleware/limites';

const router = express.Router();

/** Una única respuesta para cualquier credencial que no sirva. */
const CREDENCIALES_INVALIDAS = 'Usuario o contraseña incorrectos.';

// Las respuestas con datos de la sesión no se guardan en cachés.
router.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

/**
 * Inicio de sesión.
 *
 * CORREGIDO:
 *  - Verificación con consulta parametrizada + bcrypt (ver usuarios.service).
 *  - Mensaje genérico: no revela si la cuenta existe.
 *  - Límite de intentos fallidos por IP y por cuenta.
 *  - Se genera un identificador de sesión nuevo en cada login.
 */
router.post('/login', limiteLoginPorIp, limiteLoginPorCuenta, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    // El tipo se comprueba: el cuerpo podría traer un objeto o un arreglo.
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      return res.status(400).json({ error: 'Falta usuario o contraseña.' });
    }

    const usuario = await usuarios.autenticar(username, password);
    if (!usuario) {
      return res.status(401).json({ error: CREDENCIALES_INVALIDAS });
    }

    const datos = {
      id: usuario.id,
      username: usuario.username,
      rol: usuario.rol,
      nombre: usuario.nombre,
    };
    crearSesion(req, res, datos);

    res.json({ mensaje: `¡Bienvenido, ${usuario.nombre}!`, usuario: datos });
  } catch (err) {
    next(err);
  }
});

/**
 * Cierre de sesión.
 *
 * CORREGIDO: la sesión se elimina del servidor (una copia de la cookie deja de
 * servir) y además se borra la cookie del navegador.
 */
router.post('/logout', (req, res) => {
  destruirSesion(req);
  borrarCookieSesion(res);
  res.json({ mensaje: 'Sesión cerrada.' });
});

/** Devuelve el usuario de la sesión actual. */
router.get('/yo', (req, res) => {
  const sesion = obtenerSesion(req);
  if (!sesion) {
    return res.status(401).json({ error: 'Necesitás iniciar sesión.' });
  }
  res.json({ usuario: sesion.usuario });
});

export default router;
