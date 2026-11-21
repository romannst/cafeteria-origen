# Informe de seguridad — Cafetería Origen (Grupo 04)

Informe del TP4 de Programación IV. Cada sección documenta, por falla: qué es,
dónde está, cómo se observa, por qué ocurre, cómo se corrige, decisiones
tomadas y cómo se verifica.

La evidencia de los tests (salida real, antes y después) está en
[`evidencia/`](evidencia/).

> Cada integrante agrega su sección al final de este archivo, con el mismo formato.

---

## Cross-Site Scripting (XSS)

**Responsable:** Castellini, Nicolás
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

---

## CSRF y validación de entrada

**Responsable:** Strizzi, Román
**Fallas:** VUL-09, VUL-10, VUL-11, VUL-12

> Estado: línea de base registrada sobre `dev` integrado (commit `7551757`).
> Las correcciones y su verificación **todavía están pendientes**. Esta sección
> se completará por falla con el mismo formato de la sección XSS.

### VUL-09 · Operaciones sin protección CSRF

- **Qué es y por qué importa:** otra página puede inducir peticiones que
  modifican datos sin que la persona haya iniciado esa acción.
- **Dónde:** `src/routes/pedidos.routes.ts`, `comentarios.routes.ts`,
  `admin.routes.ts`, `auth.routes.ts`; integración pendiente en
  `src/public/js/app.js` y `admin.js`.
- **Por qué ocurre:** no hay token anti-CSRF emitido y validado por el servidor
  en las peticiones que cambian estado. El frontend no lo envía.
- **Cómo se observó manualmente:** se abrió una página HTML local ajena a la
  aplicación y se envió una sola vez, pulsando el botón, un formulario sin
  token a `POST http://localhost:8080/api/pedidos`. A diferencia del ejemplo
  de la guía, se usaron campos `items[0][productoId]` e
  `items[0][cantidad]` para que el servidor recibiera una lista válida. La
  carga útil muestra mesa `99`, cliente ficticio `Prueba CSRF`, producto
  **19** y cantidad **1**; la respuesta devuelve el pedido **28** con total
  **2500.00** y los encabezados confirman **201 Created**. Se aceptó la
  operación sin token desde una página local; conservar el pedido. Esta
  prueba del endpoint público, por sí sola, **no** demuestra envío de cookies
  de la sesión administrativa. Capturas:
  [Carga útil](evidencia/csrf-validacion/antes-csrf-pedido-28-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/antes-csrf-pedido-28-respuesta.png) y
  [Encabezados](evidencia/csrf-validacion/antes-csrf-pedido-28-encabezados.png).
  **Cambio de contraseña, observación manual separada:** se abrió el archivo
  local `prueba-csrf-contrasena.html` con un formulario `POST` sin token hacia
  `/api/admin/cambiar-contrasena`, usando la cuenta de prueba `func_admin`
  (ID **11**). Con la sesión iniciada, el envío desde ese archivo devolvió
  **200 OK** y «Contraseña actualizada»; el usuario confirmó que restableció
  la contraseña original desde el panel. La operación autenticada aceptó el
  formulario externo sin token. La respuesta incluyó el campo `password`:
  **no** reproducir ni guardar su valor en las evidencias. Captura segura de
  [Encabezados](evidencia/csrf-validacion/antes-csrf-contrasena-encabezados.png)
  (sin contraseña ni cookie visible). Por separado, el test existente no
  encontró token.
- **Corrección y decisiones (en curso):** `src/middleware/csrf.ts` emite
  `GET /api/csrf-token` con token aleatorio vinculado a la sesión autenticada
  o a una cookie anónima `HttpOnly; SameSite=Lax`. `src/app.ts` comprueba el
  token en escrituras y compara `Origin`/`Referer` cuando se envían;
  `app.js` y `admin.js` lo solicitan y mandan en `X-CSRF-Token`. El login
  conserva temporalmente compatibilidad sin token con las pruebas de auth,
  aunque se rechaza si informa un origen ajeno: **no se presenta como
  protección CSRF completa del login**. Coordinar el token obligatorio en
  login, la rotación/expiración y la política `SameSite` de la cookie `sid`
  con el trabajo de sesiones. No se deshicieron los cambios XSS.
- **Cómo se verificó hasta ahora:** el caso CSRF existente pasó con pedido
  válido y token; `tests/csrf-regresion.test.ts` comprueba rechazo sin token,
  con token de otro visitante y con origen ajeno. Typecheck y sintaxis JS
  aprobados. Quedan pendientes las pruebas funcionales y la integración
  completa tras las demás correcciones.

### VUL-10 · Pedidos sin validación suficiente

- **Qué es y por qué importa:** una cantidad negativa altera los totales; tipos
  inválidos pueden acabar en errores internos en vez de rechazarse.
- **Dónde:** `src/services/pedidos.service.ts` y
  `src/routes/pedidos.routes.ts`.
- **Por qué ocurre:** la entrada HTTP no se valida en tiempo de ejecución antes
  de procesarla o persistirla; los tipos TypeScript no validan una petición.
- **Cómo se observó manualmente:** se cambió `origen.carrito` en Local Storage,
  se recargó el sitio y se envió un pedido por la interfaz. En la primera
  observación, la **Vista previa** de Network mostraba el pedido **13**,
  mesa **4**, cliente ficticio `Demo Roman P3`, producto **19** (muffin),
  cantidad **−5** y total **−12500.00**. Una consulta de lectura a
  `GET /api/pedidos/13` lo confirmó en ese momento; no se registró el estado
  HTTP de aquella petición original. Tras cambiar de sesión, se repitió la
  demostración sin borrar pedidos: las tres capturas aportadas en la
  conversación muestran la **Carga útil** (`mesa: "6"`,
  `cliente: "Prueba Roman P3"`, producto **19**, cantidad **−5**), la
  **Respuesta** (pedido **25**, estado `abierto`, total **−12500.00**) y
  **Encabezados → General** (`POST http://localhost:8080/api/pedidos`,
  **201 Created**). Esto confirma que el servidor aceptó y guardó la cantidad
  negativa; no fue sólo un cálculo del navegador. Capturas:
  [Carga útil](evidencia/csrf-validacion/antes-pedido-25-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/antes-pedido-25-respuesta.png) y
  [Encabezados](evidencia/csrf-validacion/antes-pedido-25-encabezados.png).
- **Cantidad no numérica, observación manual:** se cambió la cantidad del
  carrito a `"abc"` y se envió el pedido desde la interfaz. La solicitud
  `POST /api/pedidos` contenía mesa `"6"`, cliente ficticio
  `Prueba Roman P3` e `items` con producto `"16"` y cantidad `"abc"`.
  La guía propone cambiar `type="number"` por `type="text"` en DevTools;
  en esta interfaz se alteró `origen.carrito` en Local Storage en su lugar,
  sin cambiar el atributo HTML. La carga útil confirma que `"abc"` llegó
  al servidor.
  El servidor respondió **500 Internal Server Error**, con el error
  `invalid input syntax for type integer: "abc"` y un stack trace en el
  cuerpo. No se comprobó de forma independiente si hubo una escritura parcial
  en la base. Esto evidencia que la cantidad no se rechaza antes de llegar a
  la base. La exposición del stack trace (`VAL-06`) se coordina con el trabajo
  de configuración. Capturas:
  [Carga útil](evidencia/csrf-validacion/antes-cantidad-abc-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/antes-cantidad-abc-respuesta.png) y
  [Encabezados](evidencia/csrf-validacion/antes-cantidad-abc-encabezados.png).
- **Otras observaciones automatizadas:** el test creó un pedido con total
  negativo (`-28700.00`) y una cantidad `"muchos"` produjo HTTP 500.
  Estos resultados se distinguen de las demostraciones manuales anteriores.
- **Corrección y decisiones:** pendientes; validar forma de los items,
  enteros positivos acotados, IDs, mesa, cliente y estados en el servidor.
  Coordinar `pedidos.service.ts` con el trabajo de parametrización SQL.
- **Cómo se verifica:** pendiente; probar los datos inválidos **con token
  CSRF válido**, y comprobar que los pedidos correctos siguen funcionando.

### VUL-11 · Reseñas sin límite de longitud

- **Dónde:** `src/routes/comentarios.routes.ts`.
- **Por qué ocurre:** no se limita el tipo ni la longitud de los campos antes
  de guardar la reseña.
- **Cómo se observó manualmente:** se quitó temporalmente `maxlength="280"`
  del campo de texto en DevTools y se envió una reseña de 50.000 caracteres
  `A` desde la interfaz, con autor ficticio `Prueba Roman P3` y calificación
  **4**. La carga útil muestra el texto extenso (50,0 kB); la respuesta
  devuelve la reseña con **ID 3** y el texto, y los encabezados confirman
  `POST http://localhost:8080/api/comentarios` con **201 Created**. El
  servidor aceptó la reseña pese al límite del formulario. Capturas:
  [Carga útil](evidencia/csrf-validacion/antes-resena-extensa-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/antes-resena-extensa-respuesta.png) y
  [Encabezados](evidencia/csrf-validacion/antes-resena-extensa-encabezados.png).
  Conservar la reseña. Por separado, el test existente había guardado una
  reseña de 5000 caracteres.
- **Corrección y verificación:** pendientes. Validar los campos en el servidor;
  repetir el caso excesivo con token válido y comprobar que una reseña normal
  se acepta y sigue mostrándose como texto tras la corrección XSS.

### VUL-12 · Subida de archivos sin restricciones

- **Dónde:** `src/routes/admin.routes.ts`, endpoint
  `POST /api/admin/subir-archivo`; publicación en `src/app.ts`.
- **Por qué ocurre:** se acepta contenido base64 y el nombre provisto por el
  cliente sin comprobar formato real, extensión, tamaño ni ruta de destino.
- **Cómo se observó manualmente:** desde Productos → «Subir imagen», se envió
  el archivo inocuo `prueba-roman-subida.html` a la instalación local. La
  carga útil muestra el nombre `.html` y su contenido base64; la respuesta
  indica `Archivo subido.`, **97 bytes** y la ruta
  `/uploads/prueba-roman-subida.html`. Los encabezados muestran
  `POST http://localhost:8080/api/admin/subir-archivo` con **200 OK**. Al
  abrir la ruta en el navegador se mostró el contenido del archivo (con un
  carácter acentuado mal codificado). Esto demuestra que se acepta y sirve
  HTML desde el mismo origen; **no** se probó ejecución de scripts. Capturas:
  [Carga útil](evidencia/csrf-validacion/antes-subida-html-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/antes-subida-html-respuesta.png),
  [Encabezados](evidencia/csrf-validacion/antes-subida-html-encabezados.png) y
  [Apertura](evidencia/csrf-validacion/antes-subida-html-apertura.png).
  Por separado, el test existente aceptó `/uploads/prueba.html`; falló en
  la primera aserción y **no** verificó dinámicamente la escritura fuera de
  `uploads/`.
- **Corrección y verificación:** pendientes. Restringir los formatos de imagen,
  comprobar los bytes reales, limitar tamaño y generar nombres en el servidor;
  aceptar imágenes válidas y rechazar contenido activo, tamaños excesivos y
  rutas manipuladas. Coordinar la ruta compartida con el trabajo de configuración.

### Verificación inicial sobre el código integrado

Ejecutada antes de corregir esta sección, en la rama `roman-strizzi` desde
`dev` (`7551757`), sólo contra la instalación local:

| Prueba | Resultado | Registro |
|---|---|---|
| `npm test` | 28/28 ✔ | [`antes-npm-test.txt`](evidencia/csrf-validacion/antes-npm-test.txt) |
| `npm run typecheck` | Sin errores ✔ | [`antes-typecheck.txt`](evidencia/csrf-validacion/antes-typecheck.txt) |
| Bloques CSRF y Validación de entrada de `seguridad.test.ts` | 0/5; fallan como se espera en la base vulnerable | [`antes-test-seguridad.txt`](evidencia/csrf-validacion/antes-test-seguridad.txt) |
| `npm run check:security` | 5/37 controles críticos; 32 pendientes y 5 recomendados pendientes | [`antes-check-security.txt`](evidencia/csrf-validacion/antes-check-security.txt) |

La batería completa de seguridad y las verificaciones **después** de corregir
siguen pendientes. El checklist ya marca `VAL-01` en verde por el control de ID
incorporado por XSS; `CSRF-02` (cookie) depende del trabajo de sesiones y
`VAL-06` (stack traces) del trabajo de configuración. Los logs iniciales de
una ejecución anterior al pull se conservan fuera del repositorio en
`D:\OpenCode\cafeteria-local\`; los archivos enlazados arriba corresponden
únicamente a la ejecución sobre la base integrada.

### Reflexión

Pendiente de redactar tras implementar y verificar las correcciones.
