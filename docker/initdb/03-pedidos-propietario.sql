-- =============================================================================
-- Dueño de cada pedido, para poder impedir el acceso a pedidos ajenos (IDOR).
--
-- Con un volumen nuevo se ejecuta solo. Sobre una base que ya existe, la
-- aplicación intenta agregar la columna al arrancar; si se conecta con un
-- usuario sin permisos sobre el esquema (origen_app), hay que correrlo a mano
-- como administrador:
--
--   docker compose exec -T db psql -U postgres -d origen \
--     < docker/initdb/03-pedidos-propietario.sql
-- =============================================================================

ALTER TABLE pedidos
    ADD COLUMN IF NOT EXISTS usuario_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL;
