/** Validación de los datos que un administrador puede modificar de un usuario. */

import { problemaDePassword } from './passwords';
import type { CambiosUsuario } from './services/usuarios.service';
import type { Rol } from './tipos';

/** Lista blanca de roles. */
const ROLES_PERMITIDOS: readonly Rol[] = ['admin', 'barista', 'mozo', 'cliente'];

type Resultado = { cambios: CambiosUsuario } | { error: string };

/**
 * Toma sólo los campos conocidos del cuerpo y valida cada uno. Los mensajes
 * son fijos: no repiten lo que mandó el cliente.
 */
export function leerCambiosUsuario(body: unknown): Resultado {
  const { username, nombre, rol, password } = (body || {}) as Record<string, unknown>;
  const cambios: CambiosUsuario = {};

  if (username !== undefined) {
    if (typeof username !== 'string' || !/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
      return { error: 'Nombre de usuario inválido (3 a 32 letras, números, punto o guion).' };
    }
    cambios.username = username;
  }
  if (nombre !== undefined) {
    if (typeof nombre !== 'string' || !nombre.trim() || nombre.length > 60) {
      return { error: 'Nombre inválido (1 a 60 caracteres).' };
    }
    cambios.nombre = nombre.trim();
  }
  if (rol !== undefined) {
    if (!ROLES_PERMITIDOS.includes(rol as Rol)) return { error: 'Rol inválido.' };
    cambios.rol = rol as Rol;
  }
  if (password !== undefined) {
    const problema = problemaDePassword(password, cambios.username);
    if (problema) return { error: problema };
    cambios.password = password as string;
  }
  if (Object.keys(cambios).length === 0) return { error: 'No hay cambios para aplicar.' };
  return { cambios };
}
