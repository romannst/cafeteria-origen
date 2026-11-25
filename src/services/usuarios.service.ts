import { randomBytes } from 'crypto';
import bcrypt from 'bcryptjs';
import * as db from '../db';
import { hashPassword, MAX_BYTES_PASSWORD } from '../passwords';
import type { Usuario, UsuarioPublico } from '../tipos';

/**
 * Servicio de usuarios.
 *
 * -----------------------------------------------------------------------------
 * CORREGIDO
 * -----------------------------------------------------------------------------
 *  - Inyección SQL en el login: la consulta es parametrizada y la contraseña
 *    ya NO forma parte del SQL; se verifica con bcrypt en la aplicación.
 *  - Contraseñas en texto plano: se guardan hasheadas. El hash se calcula
 *    acá, así ninguna ruta puede guardar el texto plano por olvido.
 *  - Exposición de credenciales: las funciones que alimentan respuestas HTTP
 *    no devuelven la columna `password`.
 *  - Asignación masiva: `actualizar` sólo admite columnas de una lista blanca.
 *    Quién puede llamarla se controla en las rutas (rol admin).
 * -----------------------------------------------------------------------------
 */

/** Únicos nombres de columna que pueden aparecer en el UPDATE. */
const COLUMNAS_PERMITIDAS = ['username', 'nombre', 'rol', 'password'] as const;

export type CambiosUsuario = Partial<Pick<Usuario, (typeof COLUMNAS_PERMITIDAS)[number]>>;

/**
 * Hash de una contraseña aleatoria que nadie conoce. Se usa cuando el usuario
 * no existe, para que esa respuesta tarde lo mismo que una clave incorrecta.
 */
const hashSenuelo = hashPassword(randomBytes(32).toString('hex'));

/**
 * Compara una contraseña con el hash guardado. Sin hash (usuario inexistente)
 * igual se hace el trabajo de bcrypt y el resultado es false.
 */
async function coincidePassword(password: string, hash: string | null): Promise<boolean> {
  const coincide = await bcrypt.compare(password, hash ?? (await hashSenuelo));
  // bcrypt ignora lo que pase de 72 bytes: esas entradas se rechazan.
  const demasiadoLarga = Buffer.byteLength(password, 'utf8') > MAX_BYTES_PASSWORD;
  return hash !== null && !demasiadoLarga && coincide;
}

/**
 * Busca un usuario por nombre de usuario exacto (query parametrizada).
 * Incluye el hash: es de uso interno y no se debe enviar al cliente.
 */
export async function buscarPorUsername(username: string): Promise<Usuario | null> {
  const { rows } = await db.query<Usuario>(
    'SELECT * FROM usuarios WHERE username = $1',
    [username]
  );
  return rows[0] || null;
}

/**
 * Autentica a un usuario comparando usuario y contraseña.
 * Devuelve el usuario (sin hash) o null, sin decir cuál de los dos falló.
 */
export async function autenticar(username: string, password: string): Promise<UsuarioPublico | null> {
  // PostgreSQL no admite el byte nulo en un texto: se trata como inexistente.
  const usuario = username.includes('\0') ? null : await buscarPorUsername(username);
  // Se llama siempre, exista o no el usuario (mismo tiempo de respuesta).
  const valida = await coincidePassword(password, usuario?.password ?? null);
  if (!usuario || !valida) return null;
  const { password: _hash, ...publico } = usuario;
  return publico;
}

/** Verifica la contraseña actual de un usuario ya autenticado. */
export async function verificarPassword(id: number, password: string): Promise<boolean> {
  const { rows } = await db.query<Pick<Usuario, 'password'>>(
    'SELECT password FROM usuarios WHERE id = $1',
    [id]
  );
  return coincidePassword(password, rows[0]?.password ?? null);
}

/** Lista todos los usuarios (para el panel de administración). */
export async function listar(): Promise<UsuarioPublico[]> {
  const { rows } = await db.query<UsuarioPublico>(
    'SELECT id, username, rol, nombre, creado_en FROM usuarios ORDER BY id'
  );
  return rows;
}

/**
 * Actualiza un usuario. Se recorre la lista blanca (no las claves recibidas),
 * por lo que un nombre de columna nunca proviene del cliente. Si llega
 * `password`, es el texto plano y se hashea antes de guardar.
 */
export async function actualizar(
  id: number | string,
  cambios: CambiosUsuario
): Promise<UsuarioPublico | null> {
  const campos: string[] = [];
  const valores: unknown[] = [];
  for (const campo of COLUMNAS_PERMITIDAS) {
    const valor = cambios[campo];
    if (valor === undefined) continue;
    valores.push(campo === 'password' ? await hashPassword(String(valor)) : valor);
    campos.push(campo + ' = $' + valores.length);
  }
  if (campos.length === 0) return null;
  valores.push(id);
  const { rows } = await db.query<UsuarioPublico>(
    `UPDATE usuarios SET ${campos.join(', ')} WHERE id = $${valores.length}
     RETURNING id, username, rol, nombre, creado_en`,
    valores
  );
  return rows[0] || null;
}

/** Cambia la contraseña de un usuario (se guarda el hash bcrypt). */
export async function cambiarPassword(
  id: number,
  nuevaPassword: string
): Promise<UsuarioPublico | null> {
  return actualizar(id, { password: nuevaPassword });
}
