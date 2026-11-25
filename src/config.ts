import path from 'path';

/**
 * Configuración de la aplicación.
 *
 * CORREGIDO — Gestión de secretos: la contraseña de la base sale sólo de la
 * variable de entorno DB_PASSWORD, sin valor por defecto en el código. Se
 * quitaron el secreto de sesión fijo y las credenciales por defecto, que no se
 * usaban (las sesiones usan identificadores aleatorios).
 */
export default {
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || 'development',

  db: {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME || 'origen',
    // Por defecto, el usuario con permisos reducidos. docker-compose.yml puede
    // indicar otro con DB_USER.
    user: process.env.DB_USER || 'origen_app',
    password: process.env.DB_PASSWORD,
  },

  uploadsDir: process.env.UPLOADS_DIR || path.join(__dirname, '..', 'uploads'),
};