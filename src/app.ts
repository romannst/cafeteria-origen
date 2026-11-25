import path from 'path';
import express from 'express';
import helmet from 'helmet';

import config from './config';
import { rutaNoEncontrada, manejadorErrores } from './middleware/errores';
import authRoutes from './routes/auth.routes';
import productosRoutes from './routes/productos.routes';
import pedidosRoutes from './routes/pedidos.routes';
import reportesRoutes from './routes/reportes.routes';
import comentariosRoutes from './routes/comentarios.routes';
import adminRoutes from './routes/admin.routes';
import debugRoutes from './routes/debug.routes';
import { obtenerToken, protegerCsrf } from './middleware/csrf';

const app = express();

app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
  })
);

app.use('/api/admin/subir-archivo', express.json({ limit: '3mb' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));


app.use('/uploads', express.static(config.uploadsDir, {
  setHeaders(res, archivo) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', 'sandbox');
    if (path.extname(archivo).toLowerCase() !== '.png') {
      res.setHeader('Content-Disposition', 'attachment');
    }
  },
}));

// Sitio web estático
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/salud', (req, res) => {
  res.json({ ok: true, servicio: 'cafeteria-origen', hora: new Date().toISOString() });
});

app.get('/api/csrf-token', obtenerToken);
app.use('/api', protegerCsrf);

app.use('/api/auth', authRoutes);
app.use('/api/productos', productosRoutes);
app.use('/api/pedidos', pedidosRoutes);
app.use('/api/reportes', reportesRoutes);
app.use('/api/comentarios', comentariosRoutes);
app.use('/api/admin', adminRoutes);

if (config.enableDebugRoutes) {
  app.use('/api/_diagnostico', debugRoutes);
}

app.use('/api', rutaNoEncontrada);

app.use(manejadorErrores);

export default app;
