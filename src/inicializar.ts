import { randomBytes } from 'crypto';
import * as db from './db';
import { CATALOGO } from './catalogo';
import { esHash, hashPassword, problemaDePassword } from './passwords';
import type { Rol } from './tipos';

interface UsuarioInicial {
  username: string;
  rol: Rol;
  nombre: string;
}

/**
 * Carga los datos iniciales (usuarios y catálogo) si la base está vacía.
 *
 * CORREGIDO — Almacenamiento inseguro de credenciales: las contraseñas se
 * guardan con bcrypt (salt por usuario). Las filas que una versión anterior
 * dejó en texto plano se convierten a hash en cada arranque.
 *
 * CORREGIDO — Credenciales de fábrica: el código no contiene contraseñas. La
 * de cada cuenta inicial sale de CLAVE_INICIAL_<USUARIO> (por ejemplo
 * CLAVE_INICIAL_VALENTINA). Si no está definida, fuera de producción se genera
 * una aleatoria y se muestra una sola vez en el log, al crear la cuenta; en
 * producción la cuenta no se crea.
 */

export const USUARIOS_INICIALES: UsuarioInicial[] = [
  { username: 'admin', rol: 'admin', nombre: 'Administración' },
  { username: 'valentina', rol: 'admin', nombre: 'Valentina' },
  { username: 'barista', rol: 'barista', nombre: 'Barista' },
  { username: 'mozo', rol: 'mozo', nombre: 'Mozo de sala' },
  { username: 'cliente', rol: 'cliente', nombre: 'Cliente' },
];

/** Contraseña con la que se crea una cuenta inicial, o null si no se debe crear. */
function passwordInicial(username: string): { clave: string; generada: boolean } | null {
  const configurada = process.env[`CLAVE_INICIAL_${username.toUpperCase()}`];
  if (configurada) {
    const problema = problemaDePassword(configurada, username);
    if (!problema) return { clave: configurada, generada: false };
    console.warn(`[origen] no se crea "${username}": ${problema}`);
    return null;
  }
  if (process.env.NODE_ENV === 'production') return null;
  return { clave: randomBytes(12).toString('base64url'), generada: true };
}

async function crearUsuariosIniciales(): Promise<void> {
  for (const usuario of USUARIOS_INICIALES) {
    const { rows } = await db.query('SELECT 1 FROM usuarios WHERE username = $1', [
      usuario.username,
    ]);
    // Si ya existe no se toca: no se pisa una contraseña que alguien cambió.
    if (rows.length > 0) continue;

    const inicial = passwordInicial(usuario.username);
    if (inicial === null) continue;

    const { rowCount } = await db.query(
      `INSERT INTO usuarios (username, password, rol, nombre)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO NOTHING`,
      [usuario.username, await hashPassword(inicial.clave), usuario.rol, usuario.nombre]
    );
    if (inicial.generada && rowCount === 1) {
      console.log(
        `[origen] cuenta "${usuario.username}" creada con la clave generada: ${inicial.clave}`
      );
    }
  }
}

/** Convierte a bcrypt las contraseñas que hayan quedado en texto plano. */
export async function migrarPasswordsEnClaro(): Promise<void> {
  const { rows } = await db.query<{ id: number; password: string }>(
    'SELECT id, password FROM usuarios'
  );
  for (const { id, password } of rows) {
    if (esHash(password)) continue;
    // La condición sobre el valor anterior evita pisar un cambio simultáneo.
    await db.query('UPDATE usuarios SET password = $1 WHERE id = $2 AND password = $3', [
      await hashPassword(password),
      id,
      password,
    ]);
  }
}

/**
 * Los scripts de docker/initdb sólo corren con el volumen vacío. Si la base ya
 * existía, se intenta agregar la columna que registra el dueño de cada pedido.
 */
async function asegurarPropietarioDePedidos(): Promise<void> {
  const { rows } = await db.query(
    `SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'pedidos' AND column_name = 'usuario_id'`
  );
  if (rows.length > 0) return;
  try {
    await db.query(
      `ALTER TABLE pedidos
         ADD COLUMN IF NOT EXISTS usuario_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL`
    );
  } catch (err) {
    console.error(
      '[origen] falta la columna pedidos.usuario_id y este usuario no puede crearla. ' +
        'Ejecutá docker/initdb/03-pedidos-propietario.sql como administrador de la base.'
    );
    throw err;
  }
}

export async function inicializarBase(): Promise<void> {
  // --- Usuarios -------------------------------------------------------------
  await crearUsuariosIniciales();
  await migrarPasswordsEnClaro();

  // --- Catálogo -------------------------------------------------------------
  for (const producto of CATALOGO) {
    await db.query(
      `INSERT INTO productos
         (nombre, tipo, variedad, tamano, gramos, precio_base, precio_por_gramo, descripcion)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (nombre) DO NOTHING`,
      [
        producto.nombre,
        producto.tipo,
        producto.variedad,
        producto.tamano,
        producto.gramos,
        producto.precio_base,
        producto.precio_por_gramo,
        producto.descripcion,
      ]
    );
  }

  // Va al final: si falla por permisos, usuarios y catálogo ya quedaron listos.
  await asegurarPropietarioDePedidos();
}