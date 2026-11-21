# Informe de seguridad — Cafetería Origen (Grupo 04)

Informe del TP4 de Programación IV. Cada sección documenta, por falla: qué es,
dónde está, cómo se observa, por qué ocurre, cómo se corrige, decisiones
tomadas y cómo se verifica.

La evidencia de los tests (salida real, antes y después) está en
[`evidencia/`](evidencia/).

> Cada integrante agrega su sección al final de este archivo, con el mismo formato.

---

## Cross-Site Scripting (XSS)

**Responsable:** Castellini, Nicolás (Integrante 2)
**Fallas:** VUL-05, VUL-06, VUL-07, VUL-08 · **OWASP:** A03:2021 — Injection

### Qué es y por qué importa

El XSS ocurre cuando datos que controla un usuario terminan insertados en la
página como **HTML** en lugar de como **texto**. El navegador no distingue si un
`<script>` lo escribió el desarrollador o un atacante: si llega al HTML, se
ejecuta con los permisos del sitio (puede leer la página, hacer peticiones a la
API con la sesión de la víctima, mostrar formularios falsos, etc.).

En el proyecto aparecían los tres tipos:

| Tipo | Cómo llega el código malicioso |
|---|---|
| **Reflejado** | El servidor devuelve en la respuesta lo que mandó el usuario. |
| **Almacenado** | Queda guardado en la base y se ejecuta en cada visita. |
| **De DOM** | El JavaScript del cliente lee la URL y la inyecta, sin pasar por el servidor. |

### Causa común

Todo el frontend (`app.js` y `admin.js`) construía el HTML concatenando strings y
lo insertaba con `innerHTML`. Existía una función `raw()` que devolvía el valor
**sin escapar**, y una `escaparHtml()` que nunca se usaba.

---

### VUL-05 · XSS reflejado en el buscador

- **Dónde:** `src/public/js/app.js`, función `renderResultado` (línea 130 original).
- **Código vulnerable:**

  ```js
  el.innerHTML = 'Resultados para <strong>' + filtros.q + '</strong> — ' + total + ' producto(s)';
  ```

- **Cómo se observó:** en el buscador del menú se escribió
  `<img src=x onerror=alert(1)>` y el navegador ejecutaba el `alert`.
- **Por qué ocurre:** el texto buscado vuelve del servidor (`filtros.q`) y se
  inserta como HTML.
- **Corrección:** el `<strong>` se crea como nodo y el texto se asigna con
  `textContent`:

  ```js
  el.replaceChildren(
    'Resultados para ',
    crearEl('strong', null, filtros.q),
    ' — ' + total + ' producto(s)'
  );
  ```

- **Verificación manual:** el mismo payload ahora se muestra literalmente
  (_Resultados para **<img src=x onerror=alert(1)>** — 0 producto(s)_), sin alert.
- **Observación:** un payload con comillas simples (`alert('XSS')`) no llegaba al
  XSS porque antes rompía la consulta SQL del catálogo (VUL-02, inyección SQL) y
  se mostraba el error de PostgreSQL.

---

### VUL-06 · XSS reflejado en los mensajes de error del servidor

- **Dónde:**
  - `src/routes/productos.routes.ts`, `GET /api/productos/:id` (línea 58 original).
  - `src/routes/auth.routes.ts`, login con usuario inexistente (línea 39 original).
- **Código vulnerable:**

  ```ts
  .json({ error: `No existe el producto "${req.params.id}".` });
  .json({ error: `El usuario "${username}" no existe en el sistema.` });
  ```

- **Cómo se observó:**
  - `GET /api/productos/<script>alert(1)</script>` devolvía el `<script>` en la
    respuesta. En la práctica el id llegaba a PostgreSQL, que fallaba al
    convertirlo a entero, y el manejador de errores devolvía ese mensaje (con el
    payload) junto con el stack trace.
  - En el login del panel, el usuario `<img src=x onerror=alert(1)>` volvía en
    el mensaje de error.
- **Por qué ocurre:** los mensajes de error repiten la entrada del cliente.
- **Corrección en `productos.routes.ts`:** se valida que el id sea un entero
  positivo **antes** de consultar la base, y el mensaje es genérico:

  ```ts
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(404).json({ error: 'Producto no encontrado.' });
  }
  const producto = await catalogo.obtener(id);
  if (!producto) {
    return res.status(404).json({ error: 'Producto no encontrado.' });
  }
  ```

- **Corrección en `auth.routes.ts`:** _pendiente._ Se resuelve con un único
  mensaje genérico (`'Usuario o contraseña incorrectos.'`), que corrige a la vez
  esta falla y la enumeración de usuarios (VUL-19, autenticación).
- **Decisiones:**
  - La validación del id es una capa adicional a la consulta parametrizada
    (**defensa en profundidad**): el payload se rechaza en la entrada y nunca
    llega a la base ni al manejador de errores.
  - Para un id inválido se responde 404 (y no 400) para no cambiar el
    comportamiento que esperan los tests funcionales.
  - Aunque el servidor devuelva HTML, el frontend ya lo muestra como texto
    (ver VUL-07 y VUL-08): los dos arreglos se complementan.

---

### VUL-07 · XSS almacenado en las reseñas (el de mayor impacto)

- **Dónde:** `src/public/js/app.js`, función `cargarReseñas` (línea 259 original).
- **Código vulnerable:**

  ```js
  cont.innerHTML = resp.data.comentarios.map(function (c) {
    return '<article class="review">' + ... + raw(c.autor) + ... + raw(c.texto) + ...;
  }).join('');
  ```

- **Cómo se observó:** se publicó una reseña con el texto
  `<script>alert('XSS almacenado')</script>`. Queda guardada en la base, así que
  se ejecuta en el navegador de **cada visitante**, incluidos los administradores.
- **Por qué ocurre:** el autor y el texto vienen de la base (los escribió
  cualquier visitante) y se insertan con `innerHTML`.
- **Corrección:** cada reseña se construye nodo por nodo con `textContent`:

  ```js
  var cabecera = crearEl('div', 'review-head');
  cabecera.append(
    crearEl('span', 'review-author', c.autor),
    crearEl('span', 'review-stars', '★'.repeat(n))
  );
  var articulo = crearEl('article', 'review');
  articulo.append(cabecera, crearEl('p', 'review-text', c.texto));
  ```

- **Decisiones:** la calificación se limita a un entero entre 0 y 5 antes de
  dibujar las estrellas, para no depender de que el servidor la valide.
- **Verificación manual:** la reseña con `<script>` ahora aparece en la lista
  como texto literal y no ejecuta nada.

---

### VUL-08 · XSS de DOM en el panel

- **Dónde:** `src/public/js/admin.js`, función `init` (línea 427 original).
- **Código vulnerable:**

  ```js
  var objetivo = params.get('vista');
  if (objetivo) { $('#panel-bienvenida').innerHTML = 'Panel ' + objetivo; }
  ```

- **Cómo se observó:** abrir
  `http://localhost:8090/admin.html?vista=<img src=x onerror=alert('DOM')>`
  ejecutaba el `alert`. Un atacante podría mandarle ese link a un administrador.
- **Por qué ocurre:** un parámetro de la URL se inserta como HTML.
- **Corrección:** el valor se valida contra una **lista blanca** de vistas y se
  muestra con `textContent`; cualquier otro valor se ignora:

  ```js
  var VISTAS = ['resumen', 'pedidos', 'productos', 'reportes', 'usuarios', 'herramientas'];
  var objetivo = new URLSearchParams(window.location.search).get('vista');
  if (objetivo && VISTAS.indexOf(objetivo) !== -1) {
    $('#panel-bienvenida').textContent = 'Panel ' + objetivo;
  }
  ```

- **Verificación manual:** con el mismo link no se ejecuta nada.

---

### Resto del frontend

Además de las cuatro fallas puntuales, se eliminó **todo** uso de `innerHTML` en
`src/public/js/`. El test y el checklist lo exigen, y cualquiera de esos lugares
era un XSS potencial:

| Archivo | Qué se reemplazó |
|---|---|
| `app.js` | Tarjetas del catálogo, mensaje de error del menú, carrito y resumen, mensajes de error de pedidos y reseñas. |
| `admin.js` | Usuario logueado, KPIs, tablas de pedidos / productos / ventas / usuarios, selects de estado y rol, función `feedback()` de todos los formularios. |

Se agregaron funciones auxiliares que construyen nodos del DOM y siempre asignan
el texto con `textContent`:

| Función | Archivo | Uso |
|---|---|---|
| `crearEl(tag, clase, texto)` | ambos | Crea un elemento con clase y texto. |
| `botonCarrito(...)` | `app.js` | Botones `+`, `−` y `Quitar` del carrito. |
| `llenarTabla(tabla, columnas, filas)` | `admin.js` | Arma cualquier tabla del panel. |
| `crearSelect(...)` | `admin.js` | Selects de estado de pedido y de rol. |
| `renderKpis(...)` | `admin.js` | Tarjetas de indicadores. |

Se eliminaron `raw()` y `escaparHtml()`.

**Decisiones:**

- Se eligió `textContent` / `createElement` en lugar de una librería
  sanitizadora (DOMPurify): el sitio nunca necesita mostrar HTML enviado por
  usuarios, así que no hace falta sanitizar; alcanza con no interpretarlo. Además
  no agrega dependencias.
- El JavaScript no usa scripts inline ni atributos `onclick`, así que es
  compatible con una CSP estricta (`script-src 'self'`).

### CSP (Content Security Policy)

_Pendiente: se configura en `app.ts` junto con las cabeceras de seguridad._ La
CSP es una segunda capa: aunque se colara un XSS, el navegador no ejecutaría
scripts que no vengan del propio sitio.

### Verificación

| Prueba | Antes | Después |
|---|---|---|
| `el servidor NO devuelve HTML sin escapar en los errores` | ✘ | ✔ |
| `el login NO devuelve HTML sin escapar en el mensaje de error` | ✘ | ✘ (pendiente: `auth.routes.ts`) |
| `el cliente NO inserta datos con innerHTML` | ✘ | ✔ |
| `npm test` (funcionales) | 28/28 ✔ | 28/28 ✔ |
| `npm run typecheck` | — | sin errores |

Comando usado para el bloque:

```bash
docker compose exec app node --import tsx --test --test-name-pattern="Cross-Site Scripting" tests/seguridad.test.ts
```

Pruebas manuales realizadas (todas muestran el payload como texto, sin ejecutar):

- Buscador: `<img src=x onerror=alert(1)>`
- Reseña: `<script>alert('XSS almacenado')</script>`
- Panel: `admin.html?vista=<img src=x onerror=alert('DOM')>`
- Login del panel con usuario `<img src=x onerror=alert(1)>`

Además se verificó que el sitio sigue funcionando igual: catálogo, filtros,
buscador, carrito, envío de pedidos, reseñas y todas las pestañas del panel.

### Reflexión

El problema de fondo era construir HTML pegando strings. En un proyecto real
conviene que la forma **por defecto** de mostrar datos sea segura (`textContent`,
o un framework que escape automáticamente) y que insertar HTML sea la excepción,
explícita y revisada. Sumar una CSP y no reflejar la entrada en los mensajes de
error agrega capas para cuando algo se escapa.