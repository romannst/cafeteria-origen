import express from 'express';
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { spawn } from 'child_process';

import config from '../config';
import * as catalogo from '../services/catalogo.service';
import * as usuarios from '../services/usuarios.service';
import { requiereSesion, requiereRol } from '../middleware/auth';
import type { Usuario } from '../tipos';
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
 * FALLA — Autorización ausente / escalada de privilegios (OWASP A01:2021)
 * -----------------------------------------------------------------------------
 * Se exige estar autenticado, pero NO se comprueba el rol: `requiereRol` está
 * importado y no se usa. Cualquier usuario autenticado (incluso con rol
 * "cliente") entra al panel y puede:
 *   - crear, editar y BORRAR productos,
 *   - cambiar contraseñas,
 *   - dar de alta usuarios y cambiarles el rol (escalada de privilegios),
 *   - ejecutar comandos en el servidor.
 *
 * Corrección: `router.use(requiereRol('admin'))` sobre las rutas sensibles.
 * -----------------------------------------------------------------------------
 */
router.use(requiereSesion);

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
 * FALLA — Asignación masiva: se actualiza cualquier campo que llegue en el
 * cuerpo, incluido el `rol`. Un usuario con rol "cliente" puede mandarse
 * `{"rol": "admin"}` y convertirse en administrador.
 */
router.put('/usuarios/:id', async (req, res, next) => {
  try {
    const { username, nombre, rol, password } = req.body || {};
    const cambios: Partial<Usuario> = {};
    if (username !== undefined) cambios.username = username;
    if (nombre !== undefined) cambios.nombre = nombre;
    if (rol !== undefined) cambios.rol = rol;
    if (password !== undefined) cambios.password = password;

    const usuario = await usuarios.actualizar(req.params.id, cambios);
    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }
    res.json(usuario);
  } catch (err) {
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
 * POST /api/admin/cambiar-contrasena
 *
 * Token CSRF verificado en src/app.ts.
 * FALLAS pendientes de autenticación: sin límite de intentos, y la contraseña nueva
 * se guarda en texto plano.
 */
router.post('/cambiar-contrasena', async (req, res, next) => {
  try {
    const { nueva } = req.body || {};
    if (!nueva) {
      return res.status(400).json({ error: 'Falta la contraseña nueva.' });
    }
    // FALLA: no se valida la longitud ni la complejidad de la contraseña.
    // (`req.usuario!`: requiereSesion ya garantizó que hay un usuario.)
    const usuario = await usuarios.cambiarPassword(req.usuario!.id, nueva);
    res.json({ mensaje: 'Contraseña actualizada.', usuario });
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

