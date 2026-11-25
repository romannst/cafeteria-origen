/**
 * Contraseñas: hash y política mínima.
 *
 * La carga inicial y los cambios de contraseña usan estas mismas reglas. La
 * comparación (bcrypt.compare) está en services/usuarios.service.ts.
 *
 *  - bcrypt genera un salt aleatorio por contraseña y lo guarda DENTRO del
 *    hash ($2a$12$<salt><hash>): dos usuarios con la misma clave tienen
 *    hashes distintos.
 *  - El costo (12) hace que cada intento sea lento a propósito.
 *  - bcrypt sólo usa los primeros 72 BYTES: lo que sobra se ignora en
 *    silencio, por eso se rechazan las contraseñas más largas.
 */

import bcrypt from 'bcryptjs';

export const COSTO_BCRYPT = 12;
export const MIN_CARACTERES = 8;
export const MAX_BYTES_PASSWORD = 72;

const FORMATO_HASH = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

export function esHash(valor: string): boolean {
  return FORMATO_HASH.test(valor);
}

export function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, COSTO_BCRYPT);
}

/**
 * Política para contraseñas NUEVAS. Devuelve el motivo del rechazo (un texto
 * fijo, sin repetir lo que mandó el cliente) o null si es aceptable.
 */
export function problemaDePassword(password: unknown, username = ''): string | null {
  if (typeof password !== 'string' || [...password].length < MIN_CARACTERES) {
    return 'La contraseña debe tener al menos 8 caracteres.';
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_BYTES_PASSWORD) {
    return 'La contraseña es demasiado larga (máximo 72 bytes).';
  }
  if (password.trim() === '') {
    return 'La contraseña no puede estar formada sólo por espacios.';
  }
  if (username && password.toLowerCase() === username.toLowerCase()) {
    return 'La contraseña no puede ser igual al nombre de usuario.';
  }
  return null;
}
