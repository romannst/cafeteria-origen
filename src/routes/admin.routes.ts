import express from 'express';
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { spawn } from 'child_process';

import config from '../config';
import * as catalogo from '../services/catalogo.service';
import * as usuarios from '../services/usuarios.service';
import { requiereSesion, requiereRol, ROLES_ADMIN } from '../middleware/auth';
import { limiteCambioPassword } from '../middleware/limites';
import { crearSesion, destruirSesionesDeUsuario } from '../middleware/sesion';
import { problemaDePassword } from '../passwords';
import { leerCambiosUsuario } from '../validacion-usuario';
import { imagenPng, MAX_BYTES } from '../validacion-archivo';
import { idValido } from '../validacion';

const router = express.Router();

const HOSTS_PERMITIDOS = new Set<string>([
  '127.0.0.1',
  'localhost',
  'db',
]);

/**
 * Rutas del panel de administración.
 *
 * -----------------------------------------------------------------------------
 * CORREGIDO — Autorización ausente / escalada de privilegios (OWASP A01:2021)
 * -----------------------------------------------------------------------------
 * Todo exige sesión y, salvo el cambio de la propia contraseña, rol admin. El
 * control está en `router.use`, antes de las rutas: una ruta nueva queda
 * protegida sin tener que acordarse, e incluso las inexistentes responden 403.
 * -----------------------------------------------------------------------------
 */
router.use(requiereSesion);

router.param('id', (req, res, next, id) => {
  if (!idValido(id)) return res.status(400).json({ error: 'ID inválido.' });
  next();
});

/**
 * POST /api/admin/cambiar-contrasena
 *
 * Disponible para cualquier usuario autenticado (cambia SÓLO la suya: el id
 * sale de la sesión, no del cuerpo). Token CSRF verificado en src/app.ts.
 *
 * CORREGIDO: pide la contraseña actual (una sesión robada no alcanza para
 * quedarse con la cuenta), limita los intentos, valida la nueva, la guarda con
 * bcrypt, cierra las demás sesiones y renueva la propia.
 */
router.post('/cambiar-contrasena', limiteCambioPassword, async (req, res, next) => {
  try {
    const { actual, nueva } = req.body || {};
    if (typeof actual !== 'string' || !actual || typeof nueva !== 'string' || !nueva) {
      return res.status(400).json({ error: 'Falta la contraseña actual o la nueva.' });
    }
    // (`req.usuario!`: requiereSesion ya garantizó que hay un usuario.)
    const yo = req.usuario!;
    const problema = problemaDePassword(nueva, yo.username);
    if (problema) {
      return res.status(400).json({ error: problema });
    }
    if (!(await usuarios.verificarPassword(yo.id, actual))) {
      return res.status(403).json({ error: 'La contraseña actual no coincide.' });
    }
    if (actual === nueva) {
      return res.status(400).json({ error: 'La contraseña nueva debe ser distinta de la actual.' });
    }
    const usuario = await usuarios.cambiarPassword(yo.id, nueva);
    destruirSesionesDeUsuario(yo.id);
    crearSesion(req, res, yo);
    res.json({ mensaje: 'Contraseña actualizada.', usuario });
  } catch (err) {
    next(err);
  }
});

// A partir de acá, sólo administradores.
router.use(requiereRol(...ROLES_ADMIN));

router.param('id', (req, res, next, id) => {
  if (!idValido(id)) return res.status(400).json({ error: 'ID inválido.' });
  next();
});

/** GET /api/admin/usuarios */
router.get('/usuarios', async (req, res, next) => {
  try {
    res.json({ usuarios: await usuarios.listar() });
  } catch (err) {
    next(err);
  }
});

/**
 * PUT /api/admin/usuarios/:id
 *
 * CORREGIDO — Escalada de privilegios y asignación masiva: sólo un admin llega
 * hasta acá, se toman únicamente campos conocidos y validados, el rol sale de
 * una lista blanca y un admin no puede cambiar su propio rol (así tampoco se
 * queda el sistema sin administrador por error). La contraseña propia se
 * cambia por /cambiar-contrasena, que exige la actual.
 */
router.put('/usuarios/:id', async (req, res, next) => {
  try {
    const leido = leerCambiosUsuario(req.body);
    if ('error' in leido) {
      return res.status(400).json({ error: leido.error });
    }
    const { cambios } = leido;
    const id = Number(req.params.id);
    const yo = req.usuario!;
    const esPropio = id === yo.id;

    if (esPropio && cambios.rol !== undefined && cambios.rol !== yo.rol) {
      return res.status(403).json({ error: 'No podés cambiar tu propio rol.' });
    }
    if (esPropio && cambios.password !== undefined) {
      return res
        .status(403)
        .json({ error: 'Para tu contraseña usá la opción "Cambiar mi contraseña".' });
    }

    const usuario = await usuarios.actualizar(id, cambios);
    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }
    if (esPropio) {
      // Se refresca la copia guardada en la sesión.
      Object.assign(req.sesion!.usuario, {
        username: usuario.username,
        nombre: usuario.nombre,
      });
    } else {
      // El usuario modificado tiene que volver a iniciar sesión.
      destruirSesionesDeUsuario(id);
    }
    res.json(usuario);
  } catch (err) {
    // El nombre de usuario es único en la base.
    if ((err as { code?: string }).code === '23505') {
      return res.status(409).json({ error: 'Ya existe un usuario con ese nombre.' });
    }
    next(err);
  }
});

/** POST /api/admin/productos — alta de producto. */
router.post('/productos', async (req, res, next) => {
  try {
    const producto = await catalogo.crear(req.body || {});
    res.status(201).json(producto);
  } catch (err) {
    // El nombre del producto es único en la base.
    if ((err as { code?: string }).code === '23505') {
      return res.status(409).json({ error: 'Ya existe un producto con ese nombre.' });
    }
    next(err);
  }
});

/** PUT /api/admin/productos/:id */
router.put('/productos/:id', async (req, res, next) => {
  try {
    const producto = await catalogo.actualizar(req.params.id, req.body || {});
    if (!producto) {
      return res.status(404).json({ error: 'Producto no encontrado.' });
    }
    res.json(producto);
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/admin/productos/:id
 *
 * Token CSRF y origen verificados por el middleware montado en src/app.ts.
 */
router.delete('/productos/:id', async (req, res, next) => {
  try {
    const producto = await catalogo.eliminar(req.params.id);
    if (!producto) {
      return res.status(404).json({ error: 'Producto no encontrado.' });
    }
    res.json(producto);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/admin/probar-conexion
 *
 * Corrección: validar el host contra una LISTA BLANCA y ejecutar el proceso
 * con `spawn('ping', ['-c', '3', host], { shell: false })`, sin pasar por el
 * shell.
 */
router.post('/probar-conexion', (req, res) => {
  const { host } = req.body || {};

  if (typeof host !== 'string' || !HOSTS_PERMITIDOS.has(host)) {
    return res.status(400).json({ error: 'Host no permitido.' });
  }

  const args = ['-c', '3', host];
  const proc = spawn('ping', args, { shell: false });

  let stdout = '';
  let stderr = '';
  let respondido = false;

  const responder = (payload: { comando: string; salida: string; error: string | null }) => {
    if (respondido) return;
    respondido = true;
    res.json(payload);
  };

  proc.stdout.on('data', (chunk) => {
    stdout += chunk.toString();
  });

  proc.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  proc.on('error', (err) => {
    responder({
      comando: `ping ${args.join(' ')}`,
      salida: stdout,
      error: stderr || err.message,
    });
  });

  proc.on('close', (code) => {
    responder({
      comando: `ping ${args.join(' ')}`,
      salida: stdout,
      error: stderr || (code !== 0 && code !== null ? `Proceso finalizó con código ${code}` : null),
    });
  });
});

/**
 * POST /api/admin/subir-archivo
 *
 * -----------------------------------------------------------------------------
 * Línea de base: carga de archivos sin restricciones (OWASP A04:2021).
 * -----------------------------------------------------------------------------
 * Ahora sólo acepta PNG RGB/RGBA verificados y acotados; el nombre lo genera
 * el servidor. Los archivos anteriores no se borran, pero se descargan si
 * no son PNG.
 *
 * La carpeta uploads está fuera del árbol de archivos públicos, y sólo se
 * sirve por la ruta controlada en app.ts.
 * -----------------------------------------------------------------------------
 */
router.post('/subir-archivo', (req, res, next) => {
  try {
    const { nombre, contenidoBase64 } = req.body || {};

    if (!nombre || !contenidoBase64) {
      return res.status(400).json({ error: 'Falta el archivo.' });
    }

    if (typeof nombre !== 'string' || path.basename(nombre) !== nombre ||
      path.win32.basename(nombre) !== nombre ||
      path.extname(nombre).toLowerCase() !== '.png' ||
      typeof contenidoBase64 !== 'string' ||
      contenidoBase64.length > Math.ceil(MAX_BYTES / 3) * 4) {
      return res.status(400).json({ error: 'Sólo se aceptan PNG de hasta 2 MB.' });
    }
    const buffer = imagenPng(nombre, contenidoBase64);
    if (!buffer) {
      return res.status(400).json({ error: 'Sólo se aceptan PNG válidos de hasta 2 MB.' });
    }
    fs.mkdirSync(config.uploadsDir, { recursive: true });

    const archivo = `${randomUUID()}.png`;
    const destino = path.join(config.uploadsDir, archivo);
    fs.writeFileSync(destino, buffer, { flag: 'wx' });

    res.json({
      mensaje: 'Archivo subido.',
      url: `/uploads/${archivo}`,
      bytes: buffer.length,
    });
  } catch (err) {
    next(err);
  }
});

export default router;

