# Informe de seguridad — Cafetería Origen (Grupo 04)

Informe del TP4 de Programación IV. Cada sección documenta, por falla: qué es,
dónde está, cómo se observa, por qué ocurre, cómo se corrige, decisiones
tomadas y cómo se verifica.

La evidencia de los tests (salida real, antes y después) está en
[`evidencia/`](evidencia/).

> Cada integrante agrega su sección al final de este archivo, con el mismo formato.

---

## Inyección SQL (SQL Injection)

**Responsable:** Ramos, Nikolás (Integrante 1)
**Fallas:** VUL-01, VUL-02, VUL-03, VUL-04 · **OWASP:** A03:2021 — Injection

### Qué es y por qué importa

La inyección SQL ocurre cuando datos que controla un usuario se concatenan
directamente en la cadena de una consulta SQL en lugar de enviarse como
parámetros separados. El motor de base de datos (PostgreSQL) no distingue si
las comillas o los operadores los escribió el desarrollador o un atacante: si
forman parte de la consulta, se interpretan como instrucciones SQL (permitiendo
eludir controles de acceso, alterar filtros o leer información de otras tablas).

En el proyecto aparecían distintos vectores de inyección:

| Tipo | Cómo se explota en la aplicación | 
| ----- | ----- | 
| **Bypass de autenticación** | Alterar la condición `WHERE` en el login para ingresar sin conocer la contraseña. | 
| **Inyección en filtros dinámicos** | Manipular cláusulas `AND` o `WHERE` para ampliar los resultados devueltos. | 
| **Inyección basada en `UNION`** | Anexar consultas sobre otras tablas (`usuarios`) para exfiltrar datos sensibles. | 

### Causa común

En las capas de servicio del proyecto (`usuarios.service.ts`,
`catalogo.service.ts`, `pedidos.service.ts` y `reportes.service.ts`) se
construían las sentencias SQL concatenando variables de entrada mediante
template strings (`${...}`), confiando en que los valores recibidos no
contendrían caracteres especiales de SQL.

---

### VUL-01 · Inyección SQL en el login

- **Dónde:** `src/services/usuarios.service.ts` (línea 42).
- **Código vulnerable:**

  ```js
  const sql = `SELECT * FROM usuarios WHERE username = '${username}' AND password = '${password}'`;
  const { rows } = await db.query(sql);
  ```

- **Cómo se observó:** en el formulario de login del panel se ingresó el
  usuario `' OR 1=1 --` con cualquier contraseña y el sistema permitió ingresar
  como `admin`. También se verificó con `admin'--` para acceder sin contraseña.
- **Por qué ocurre:** `username` y `password` se concatenan directamente al
  texto SQL, permitiendo que las comillas cierren la cadena y modifiquen la
  lógica del `WHERE`.
- **Corrección:** se parametrizan las consultas con marcadores posicionales
  (`$1`) y se verifica la contraseña mediante hashing (`bcrypt.compare`) en
  lugar de compararla en texto plano:

  ```js
  const { rows } = await db.query('SELECT * FROM usuarios WHERE username = $1', [username]);
  const usuario = rows[0];
  if (!usuario) return null;
  const coincide = await bcrypt.compare(password, usuario.password);
  return coincide ? usuario : null;
  ```

- **Verificación manual:** los payloads de bypass en el login dejan de
  autenticar sin credenciales válidas y se tratan como cadenas literales.
- **Decisiones:** parametrizar la consulta debe ir acompañado de `bcrypt.compare`
  (control **AUTH-03**), ya que mantener contraseñas en texto plano en la base
  de datos (VUL-13) sigue exponiendo las cuentas ante cualquier filtración.

---

### VUL-02 · Inyección SQL en los filtros del catálogo

* **Dónde:** `src/services/catalogo.service.ts` (líneas 40–43 y también en `obtener(id)`).

* **Código vulnerable:**

  ```ts
  if (tipo) sql += ` AND tipo = '${tipo}'`;
  if (variedad) sql += ` AND variedad = '${variedad}'`;
  if (q) sql += ` AND (nombre ILIKE '%${q}%' OR descripcion ILIKE '%${q}%')`;
  ```

* **Cómo se observó:** en el buscador del menú se escribió `q = ' OR '1'='1` (o
  `' OR 1=1 --`) y la API devolvió los 20 productos del catálogo completo en
  lugar de acotar los resultados.

* **Por qué ocurre:** los parámetros `tipo`, `variedad` y `q` (además de `id`
  en `obtener`) se concatenan directamente en el SQL dinámico sin escapar ni
  parametrizar.

* **Corrección:** construir la consulta de forma parametrizada (`$1`, `$2`, …)
  acumulando las condiciones y enviando los valores en un arreglo de parámetros
  separado de la sentencia SQL, y parametrizar/validar también el `id` en
  `obtener`:

  ```ts
  const condiciones: string[] = ['activo = true'];
  const params: unknown[] = [];

  if (tipo) {
    params.push(tipo);
    condiciones.push(`tipo = $${params.length}`);
  }
  if (variedad) {
    params.push(variedad);
    condiciones.push(`variedad = $${params.length}`);
  }
  if (q) {
    params.push(`%${q}%`);
    condiciones.push(`(nombre ILIKE $${params.length} OR descripcion ILIKE $${params.length})`);
  }

  const sql = `SELECT * FROM productos WHERE ${condiciones.join(' AND ')} ORDER BY tipo, variedad NULLS FIRST, id`;
  const { rows } = await db.query<Producto>(sql, params);
  ```

* **Verificación manual:** al buscar `' OR '1'='1` en el catálogo, el motor lo
  evalúa como texto literal dentro de `ILIKE` y devuelve 0 coincidencias sin
  alterar la consulta.

* **Observación:** esta falla también provocaba que payloads de XSS con
  comillas simples (como `alert('XSS')` en VUL-05) rompieran la sintaxis SQL y
  expusieran errores de PostgreSQL antes de llegar al frontend. Asimismo, se
  corrigió la concatenación directa en `obtener(id)` parametrizando el `id` y
  validando que sea un entero positivo.

---

### VUL-03 · Inyección SQL en el filtro por mesa y validación en creación de pedidos

- **Dónde:** `src/services/pedidos.service.ts` (`listar` y `crear`).

- **Código vulnerable:**

  ```ts
  if (mesa) sql += ` WHERE mesa = '${mesa}'`;
  ```

* **Cómo se observó:** al realizar la petición `GET /api/pedidos?mesa=' OR '1'='1`
  la consulta devolvía los pedidos de **todas** las mesas en lugar de filtrar
  únicamente por la mesa solicitada.

* **Por qué ocurre:** el parámetro `mesa` se concatena directamente en la
  cláusula `WHERE` sin parametrización.

* **Corrección:** reemplazar la interpolación por un parámetro vinculado
  (`WHERE mesa = $1`) pasando `[mesa]` como arreglo de parámetros a `db.query`:

  ```ts
  const params: unknown[] = [];
  let sql = 'SELECT * FROM pedidos';

  if (mesa) {
    params.push(mesa);
    sql += ` WHERE mesa = $${params.length}`;
  }

  sql += ' ORDER BY id DESC';
  const { rows } = await db.query(sql, params);
  ```

* **Verificación manual:** la petición con `' OR '1'='1` ya no amplía el
  resultado y devuelve una lista vacía al no existir una mesa con ese nombre
  literal.

---

### VUL-04 · Inyección SQL vía `UNION` en reporte de ventas por origen

* **Dónde:** `src/services/reportes.service.ts` (`ventasPorVariedad`).

* **Código vulnerable:**

  ```ts
  const sql = `
    SELECT pr.variedad, pr.nombre, SUM(pi.cantidad) AS unidades,
           SUM(pi.cantidad * pi.precio_unitario) AS total
      FROM pedido_items pi
      JOIN productos pr ON pr.id = pi.producto_id
     GROUP BY pr.variedad, pr.nombre
    HAVING pr.variedad = '${variedad}'`;

  const { rows } = await db.query<VentaPorVariedad>(sql);

* **Cómo se observó:** al consultar
  `GET /api/reportes/ventas-por-variedad?variedad=Brasil' UNION SELECT username, password, 1, 1 FROM usuarios--`
  el reporte anexaba los registros de la tabla `usuarios`, exponiendo nombres
  de usuario y contraseñas en texto plano.

* **Por qué ocurre:** el parámetro `variedad` se concatena directamente en la
  consulta de reporte, permitiendo cerrar la cadena e inyectar una sentencia
  `UNION SELECT` sobre otras tablas de la base.

* **Corrección:** parametrizar la consulta (`WHERE pr.variedad = $1`) y
  validar previamente el parámetro contra una **lista blanca** de orígenes
  permitidos (`Brasil`, `Colombia`, `Etiopía`):

  ```ts
  const VARIEDADES_PERMITIDAS = ['Brasil', 'Colombia', 'Etiopía'];

  if (!VARIEDADES_PERMITIDAS.includes(variedad)) {
    throw new Error('Variedad no válida.');
  }

  const sql = `
    SELECT pr.nombre, pr.variedad, SUM(ip.cantidad) AS unidades, SUM(ip.subtotal) AS total
    FROM items_pedido ip
    JOIN productos pr ON pr.id = ip.producto_id
    WHERE pr.variedad = $1
    GROUP BY pr.id, pr.nombre, pr.variedad
    ORDER BY total DESC
  `;
  const { rows } = await db.query(sql, [variedad]);
  ```

* **Decisiones:** combinar la consulta parametrizada con validación por lista
  blanca aplica **defensa en profundidad**, rechazando valores fuera de dominio
  antes de consultar la base de datos.

* **Verificación manual:** el payload con `UNION SELECT` es rechazado por la
  validación de entrada y no expone datos de otras tablas.

---

### Verificación

| Prueba / Verificación | Antes | Después |
| :--- | :---: | :---: |
| `el login NO acepta el bypass con payload SQL` (VUL-01) | ✘ | ✔ |
| `el login NO acepta el payload que comenta la contraseña` (VUL-01) | ✘ | ✔ |
| `la búsqueda del catálogo NO se puede ampliar con SQL` (VUL-02) | ✘ | ✔ |
| `el filtro por origen NO se puede ampliar con SQL` (VUL-02) | ✘ | ✔ |
| `el filtro por mesa NO se puede ampliar con SQL` (VUL-03) | ✘ | ✔ |
| `el reporte por origen NO filtra otras tablas con UNION` (VUL-04) | ✘ | ✔ |
| `la aplicación NO se conecta con un superusuario de la base` | ✘ | ✘ *(configuración de conexión/usuario BD, fuera de servicios SQLi)* |

Comando usado para ejecutar las pruebas de seguridad:

```bash
npm run test:seguridad
```

*(O en contenedor: `docker compose exec app npm run test:seguridad`)*

Pruebas manuales realizadas (sin alterar datos sensibles ni exfiltrar información):

* **Login (`VUL-01`):** payloads como `' OR 1=1 --` y `admin'--` ya no permiten ingresar sin credenciales válidas.
* **Catálogo (`VUL-02`):** búsqueda con `q = ' OR '1'='1` y filtro `variedad = Colombia' OR '1'='1` no amplían resultados fuera del filtro ni rompen la consulta.
* **Pedidos (`VUL-03`):** consulta `GET /api/pedidos?mesa=' OR '1'='1` no devuelve pedidos de todas las mesas y las validaciones de entrada en `crear` rechazan datos inválidos.
* **Reportes (`VUL-04`):** consulta `GET /api/reportes/ventas-por-variedad?variedad=Brasil' UNION SELECT username, password, 1, 1 FROM usuarios--` no expone datos de `usuarios` y respeta la lista blanca + parametrización.

---

### Reflexión

El origen de estas fallas era armar sentencias SQL concatenando strings con datos de entrada (`${...}`), tratando valores externos como parte de la sintaxis de la consulta en lugar de pasarlos como parámetros vinculados.

En una aplicación real, el estándar por defecto debe ser **siempre consultas parametrizadas** (`$1`, `$2`, …) y validación estricta de entradas (tipos, rangos, longitudes y listas blancas cuando el dominio es cerrado), dejando la construcción dinámica de identificadores o cláusulas fuera del alcance de la entrada del usuario. Combinar parametrización, validación en servidor y hashing de contraseñas reduce drásticamente el impacto de cualquier entrada maliciosa.

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

- **Corrección en `auth.routes.ts`:** resuelta por el integrante 4. El login
  responde siempre el mismo mensaje (`'Usuario o contraseña incorrectos.'`), sin
  repetir el usuario, lo que corrige a la vez esta falla y la enumeración de
  usuarios (VUL-19). Además, `errores.ts` dejó de devolver la URL pedida en
  "Ruta no encontrada" (control XSS-02).
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

Configurada por el integrante 5 en `app.ts` con `helmet`, coordinada con este
bloque: `script-src 'self'` (sin `'unsafe-inline'`), `object-src 'none'` y
`frame-ancestors 'none'`. Funciona sin romper nada porque el frontend ya no usa
scripts inline ni atributos `onclick`. Es una segunda capa: aunque se colara un
XSS, el navegador no ejecutaría scripts que no vengan del propio sitio.

### Verificación

| Prueba | Antes | Después |
|---|---|---|
| `el servidor NO devuelve HTML sin escapar en los errores` | ✘ | ✔ |
| `el login NO devuelve HTML sin escapar en el mensaje de error` | ✘ | ✔ |
| `el cliente NO inserta datos con innerHTML` | ✘ | ✔ |
| `npm run check:security` (XSS-01 a XSS-04) | ✘ | ✔ |
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

Evidencia en Docker (después de las correcciones):
[npm test](evidencia/xss/despues-npm-test.txt) ·
[test:seguridad](evidencia/xss/despues-test-seguridad.txt) ·
[check:security](evidencia/xss/despues-check-security.txt) ·
[buscador](evidencia/xss/despues-buscador.jpg) ·
[reseña](evidencia/xss/despues-resena.jpg) ·
[panel 1](evidencia/xss/despues-panel-1.jpg) ·
[panel 2](evidencia/xss/despues-panel-2.jpg) ·
[login](evidencia/xss/despues-login.jpg)

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
> Implementación propia y evidencia de los casos descritos documentadas.
> El cierre local conserva dependencias de sesiones, configuración e integración;
> no equivale a la aprobación global de seguridad del proyecto.

### VUL-09 · Operaciones sin protección CSRF

- **Qué es y por qué importa:** otra página puede inducir peticiones que
  modifican datos sin que la persona haya iniciado esa acción.
- **Dónde:** `src/routes/pedidos.routes.ts`, `comentarios.routes.ts`,
  `admin.routes.ts`, `auth.routes.ts`, `src/public/js/app.js` y `admin.js`.
- **Por qué ocurría:** antes de la corrección no había token anti-CSRF emitido
  y validado por el servidor en las peticiones que cambian estado; el
  frontend tampoco lo enviaba.
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
  **200 OK** y «Contraseña actualizada»; después de la prueba se restableció
  la contraseña original desde el panel. La operación autenticada aceptó el
  formulario externo sin token. La respuesta incluyó el campo `password`:
  **no** reproducir ni guardar su valor en las evidencias. Captura segura de
  [Encabezados](evidencia/csrf-validacion/antes-csrf-contrasena-encabezados.png)
  (sin contraseña ni cookie visible). Por separado, el test existente no
  encontró token.
- **Corrección y decisiones:** `src/middleware/csrf.ts` emite
  `GET /api/csrf-token` con token aleatorio vinculado a la sesión autenticada
  o a una cookie anónima `HttpOnly; SameSite=Lax`. `src/app.ts` comprueba el
  token en escrituras y compara `Origin`/`Referer` cuando se envían;
  `app.js` y `admin.js` lo solicitan y mandan en `X-CSRF-Token`, incluido
  el login del panel. Se eliminó la excepción inicial del login y se adaptaron
  los clientes de pruebas para enviar token. La cookie `sid` incorpora
  `SameSite=Lax`. Los tokens recibidos deben ser hexadecimales de 64 caracteres
  antes de compararlos, evitando errores internos por diferencias de bytes
  con texto Unicode. El token anónimo no sirve tras autenticarse; el token
  autenticado tampoco sirve cuando el navegador ya no envía la sesión.
  El almacén de tokens en memoria aún no tiene limpieza ni TTL propio:
  coordinar su ciclo de vida con la rotación, expiración e invalidación de
  sesiones. No se deshicieron los cambios XSS.
- **Cómo se verificó hasta ahora:** el caso CSRF existente pasó con pedido
  válido y token; `tests/csrf-regresion.test.ts` comprueba rechazo sin token,
  con token de otro visitante y con origen ajeno. Typecheck y sintaxis JS
  aprobados; `npm test` conserva 28/28. Al reenviar manualmente el formulario
  local que antes había creado el pedido 28, `POST /api/pedidos` devolvió
  **403 Forbidden** con «Origen de petición no permitido»:
  [Respuesta](evidencia/csrf-validacion/despues-csrf-pedido-respuesta.png) y
  [Encabezados](evidencia/csrf-validacion/despues-csrf-pedido-encabezados.png).
  Esto comprueba el rechazo **por origen** en ese intento, no la validación
  del token por sí sola; esta última se comprobó con las regresiones.
  El login, `SameSite` y la separación de tokens entre visitantes y sesiones
  se verificaron posteriormente con las pruebas de cierre; el ciclo de vida
  de las sesiones requiere integración con su bloque. Además, se inició
  sesión manualmente con una cuenta administrativa de prueba y se accedió
  correctamente al panel tras exigir token en el login; esta comprobación
  **no tiene captura** y no expone credenciales. Con la sesión abierta, se
  repitió una sola vez el formulario local externo dirigido a
  `POST http://localhost:8080/api/admin/cambiar-contrasena`: los encabezados
  indicaron **403 Forbidden** y la respuesta fue
  `{"error":"Origen de petición no permitido."}`. Este resultado se
  comunicó en la conversación, **sin captura**; acredita rechazo por origen,
  no una prueba aislada del token ni una comprobación independiente de la
  contraseña almacenada.

### VUL-10 · Pedidos sin validación suficiente

- **Qué es y por qué importa:** una cantidad negativa altera los totales; tipos
  inválidos pueden acabar en errores internos en vez de rechazarse.
- **Dónde:** `src/services/pedidos.service.ts` y
  `src/routes/pedidos.routes.ts`.
- **Por qué ocurría:** la entrada HTTP no se validaba en tiempo de ejecución
  antes de procesarla o persistirla; los tipos TypeScript no validan peticiones.
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
- **Corrección y decisiones:** `src/validacion.ts` comprueba la
  forma de los items, IDs enteros positivos, cantidades entre 1 y 100,
  hasta 20 items, mesa numérica (1–10 caracteres), nombre (2–40) y estados
  permitidos antes de escribir. Los IDs se acotan a 1..2147483647, rango de
  las columnas INTEGER de PostgreSQL. También se validan los parámetros
  `:id` de pedidos y del panel antes de llamar al servicio; el catálogo
  conserva su respuesta genérica 404 para IDs inválidos. La ruta transforma
  los números recibidos de formularios a números reales; un producto
  inexistente devuelve 400.
  Coordinar los cambios puntuales en `pedidos.service.ts` con el trabajo de
  parametrización SQL.
- **Cómo se verificó hasta ahora:** `tests/validacion-regresion.test.ts`
  envió token CSRF válido, obtuvo 400 para −5, `"abc"`, cero, decimal y 101,
  comprobó que no aparecieron pedidos de la prueba y creó correctamente un
  pedido legítimo. `npm test` aprobó 28/28. En la comprobación manual
  posterior, la interfaz envió mesa `4`, cliente ficticio `Prueba Roman`,
  producto `3` y cantidad **−5**. El `POST /api/pedidos` devolvió
  **400 Bad Request** con «Datos del pedido inválidos»:
  [Carga útil](evidencia/csrf-validacion/despues-cantidad-negativa-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/despues-cantidad-negativa-respuesta.png)
  y [Encabezados](evidencia/csrf-validacion/despues-cantidad-negativa-encabezados.png).
  La captura muestra también un subtotal negativo calculado en el navegador
  a partir del carrito alterado; no equivale a un pedido guardado. El 400
  acredita que el servidor rechazó esa petición, aunque estas capturas
  no verifican por sí solas el estado de la base de datos.
  Se repitió manualmente el caso no numérico desde la interfaz: la carga
  útil incluyó mesa `4`, cliente ficticio `Prueba Roman`, producto `13`
  y cantidad **`"abc"`**. `POST /api/pedidos` devolvió **400 Bad Request**
  con «Datos del pedido inválidos», sin el error PostgreSQL ni el stack
  trace del caso anterior:
  [Carga útil](evidencia/csrf-validacion/despues-cantidad-abc-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/despues-cantidad-abc-respuesta.png) y
  [Encabezados](evidencia/csrf-validacion/despues-cantidad-abc-encabezados.png).
  El total `0,00` visible en la página es un cálculo del cliente con el
  carrito alterado, no un pedido aceptado. Tampoco se verificó de manera
  independiente el estado de la base tras este envío. Como comprobación
  manual de una operación legítima, la respuesta de un pedido desde la
  interfaz devolvió el pedido **47**, mesa `4`, cliente ficticio
  `Prueba pedido normal`, estado `abierto` y total **13180.00**: producto
  **6** (Espresso Taza grande Colombia) y producto **20** (Porción de
  torta selva negra), ambos con cantidad **1**. Se registró el cuerpo de
  la respuesta en la conversación; no se aportaron captura ni estado HTTP
  de esa petición. Este resultado muestra que el flujo legítimo devuelve
  un pedido, pero no verifica por sí solo el token CSRF ni una consulta
  independiente a la base de datos.

### VUL-11 · Reseñas sin límite de longitud

- **Dónde:** `src/routes/comentarios.routes.ts`.
- **Por qué ocurría:** no se limitaba el tipo ni la longitud de los campos
  antes de guardar la reseña.
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
- **Corrección y verificación:** `src/validacion.ts` exige autor
  entre 2 y 40 caracteres, texto entre 3 y 280 y calificación entera de 1 a
  5 en el servidor. La prueba de regresión, con token válido, rechazó 50.000
  caracteres con 400 y aceptó una reseña normal con 201. En la repetición
  manual, la carga útil de `POST /api/comentarios` mostró autor ficticio
  `Prueba Roman`, calificación **5** y texto de **50,0 kB**; el servidor
  respondió **400 Bad Request** con «Datos de reseña inválidos»:
  [Carga útil](evidencia/csrf-validacion/despues-resena-extensa-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/despues-resena-extensa-respuesta.png)
  y [Encabezados](evidencia/csrf-validacion/despues-resena-extensa-encabezados.png).
  Las capturas muestran el rechazo de la petición, pero no verifican por
  separado el estado de la base. La prueba manual con un texto breve de
  letras `a`, autor ficticio `Prueba Roman` y calificación **3** devolvió la
  reseña **ID 8** con **201 Created**; la página mostró el texto y el
  mensaje de confirmación:
  [Carga útil](evidencia/csrf-validacion/despues-resena-normal-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/despues-resena-normal-respuesta.png)
  y [Encabezados](evidencia/csrf-validacion/despues-resena-normal-encabezados.png).
  Se conserva esa reseña. Esta prueba comprueba publicación y visualización
  del texto, **no** demuestra por sí sola el tratamiento seguro de etiquetas
  HTML; esa verificación corresponde a la evidencia XSS.

### VUL-12 · Subida de archivos sin restricciones

- **Dónde:** `src/routes/admin.routes.ts`, endpoint
  `POST /api/admin/subir-archivo`; publicación en `src/app.ts`.
- **Por qué ocurría:** se aceptaba contenido base64 y el nombre provisto por el
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
- **Corrección y verificación:** sólo se admite PNG RGB/RGBA de
  8 bits con extensión `.png`, base64 válido, firma y estructura de chunks/CRC
  coherentes y datos de imagen descomprimibles; hasta 2 MB, con dimensiones y
  salida descomprimida acotadas. Se genera un nombre UUID en el servidor y se
  escribe con exclusividad en `uploads/` sin usar el nombre recibido como
  ruta. Se decidió **no aceptar SVG ni JPEG** en este bloque: PNG cubre el
  uso de imagen sin incorporar formatos activos. La publicación de
  `/uploads/` añade `nosniff`, CSP `sandbox` y descarga forzada para archivos
  anteriores no PNG, sin borrar la demostración. La prueba de regresión con
  sesión y token válidos rechazó HTML y contenido no PNG, aceptó un PNG
  generado y comprobó su lectura. En la repetición manual desde el panel,
  la carga útil mostró el archivo `prueba-roman-subida.html`; la respuesta
  fue **400 Bad Request** con «Sólo se aceptan PNG de hasta 2 MB»:
  [Carga útil](evidencia/csrf-validacion/despues-subida-html-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/despues-subida-html-respuesta.png)
  y [Encabezados](evidencia/csrf-validacion/despues-subida-html-encabezados.png).
  Estas capturas acreditan el rechazo de la petición, no una inspección
  independiente del almacenamiento. En otra prueba manual desde el panel,
  `prueba-subida.png` se aceptó con **200 OK**; la respuesta indicó
  «Archivo subido.», **11.922 bytes** y una ruta `/uploads/` con nombre UUID:
  [Carga útil](evidencia/csrf-validacion/despues-subida-png-carga-util.png),
  [Respuesta](evidencia/csrf-validacion/despues-subida-png-respuesta.png)
  y [Encabezados](evidencia/csrf-validacion/despues-subida-png-encabezados.png).
  La lectura del PNG está cubierta por la regresión automática. Además,
  Se abrió manualmente la ruta `/uploads/` devuelta y la imagen se visualizó
  correctamente; esta comprobación visual **no tiene captura**.
  Coordinar la publicación compartida con el trabajo de configuración.

### Verificación inicial sobre el código integrado

Ejecutada antes de corregir esta sección, en la rama `roman-strizzi` desde
`dev` (`7551757`), sólo contra la instalación local:

| Prueba | Resultado | Registro |
|---|---|---|
| `npm test` | 28/28 ✔ | [`antes-npm-test.txt`](evidencia/csrf-validacion/antes-npm-test.txt) |
| `npm run typecheck` | Sin errores ✔ | [`antes-typecheck.txt`](evidencia/csrf-validacion/antes-typecheck.txt) |
| Bloques CSRF y Validación de entrada de `seguridad.test.ts` | 0/5; fallan como se espera en la base vulnerable | [`antes-test-seguridad.txt`](evidencia/csrf-validacion/antes-test-seguridad.txt) |
| `npm run check:security` | 5/37 controles críticos; 32 pendientes y 5 recomendados pendientes | [`antes-check-security.txt`](evidencia/csrf-validacion/antes-check-security.txt) |

En esta línea de base aún no se había ejecutado la batería completa de
seguridad ni las verificaciones posteriores. El checklist ya marcaba `VAL-01`
en verde por el control de ID
incorporado por XSS; `CSRF-02` (cookie) depende del trabajo de sesiones y
`VAL-06` (stack traces) del trabajo de configuración. Los logs iniciales de
una ejecución anterior al pull se conservan fuera del repositorio en
`D:\OpenCode\cafeteria-local\`; los archivos enlazados arriba corresponden
únicamente a la ejecución sobre la base integrada.

### Verificación inicial después de las correcciones propias (histórica)

Las pruebas se ejecutaron con Docker local y no borraron los pedidos ni las
reseñas de demostración; las regresiones eliminaron únicamente sus datos
marcados. Se registraron comprobaciones manuales posteriores en el navegador
para los casos descritos arriba; otras operaciones y la integración de los
cambios compartidos siguen pendientes.

| Prueba | Resultado | Registro |
|---|---|---|
| `npm test` | 28/28 ✔ | [`despues-npm-test.txt`](evidencia/csrf-validacion/despues-npm-test.txt) |
| `npm run typecheck` | Sin errores ✔ | [`despues-typecheck.txt`](evidencia/csrf-validacion/despues-typecheck.txt) |
| Regresiones propias de CSRF, validación y subidas | 9/9 ✔; entradas inválidas probadas con token válido | [`despues-regresiones.txt`](evidencia/csrf-validacion/despues-regresiones.txt) |
| `npm run check:security` | 10/37 controles críticos aprobados; resultado global **fallido** por controles de otros bloques y dependencias `CSRF-02` y `VAL-06` | [`despues-check-security.txt`](evidencia/csrf-validacion/despues-check-security.txt) |

Además pasaron los dos casos específicos de CSRF y archivos de
`tests/seguridad.test.ts`
([registro](evidencia/csrf-validacion/despues-test-seguridad-seleccion.txt)).
En aquella ejecución, el resto del bloque de validación de esa batería
no constituía evidencia suficiente por sí solo: sus peticiones inválidas
no mandaban token y podían recibir 403 por CSRF en vez de 400 por validación.
Por eso se añadieron regresiones propias con token y comprobación explícita
de estado 400. En el cierre posterior también se corrigió la batería original:
las tres entradas inválidas envían token y exigen 400; el pedido legítimo
de CSRF exige 201. `CSRF-02` se completó después de este registro histórico.

### Verificación de cierre tras revisar la lista de tareas

Se ejecutaron nuevamente los controles pertinentes contra Docker local.
Las regresiones cubren IDs inválidos y fuera del rango de la base, estados
permitidos y rechazados, límites de campos e ítems, límites de reseñas,
login con token, separación entre token anónimo y autenticado, `SameSite`,
contenido disfrazado de PNG, base64 inválido, corrupción de PNG y rutas
Unix/Windows. Una prueba del script real del panel con DOM y red simulados
comprueba que el formulario de login solicita y envía el token; no se
presenta como una nueva prueba manual de navegador.

| Prueba | Resultado | Registro |
|---|---|---|
| `npm test` | 28/28 ✔ | [Log](evidencia/csrf-validacion/cierre-npm-test.txt) |
| `npm run typecheck` | Sin errores ✔ | [Log](evidencia/csrf-validacion/cierre-typecheck.txt) |
| Regresiones propias | 17/17 ✔ | [Log](evidencia/csrf-validacion/cierre-regresiones.txt) |
| Bloques CSRF y Validación de `seguridad.test.ts` | 5/5 ✔, con token válido en las pruebas de validación | [Log](evidencia/csrf-validacion/cierre-bloques-seguridad.txt) |
| `npm run check:security` | CSRF-01..04 y VAL-01..05 ✔; VAL-06 pendiente. Global 11/37, **fallido** | [Log](evidencia/csrf-validacion/cierre-check-security.txt) |

Comandos reproducibles dentro del contenedor:

```sh
npm test
npm run typecheck
node --import tsx --test --test-concurrency=1 tests/csrf-regresion.test.ts tests/validacion-regresion.test.ts tests/subidas-regresion.test.ts
node --import tsx --test --test-concurrency=1 --test-name-pattern="Seguridad · (CSRF|Validación de entrada)" tests/seguridad.test.ts
npm run check:security
```

Las adaptaciones a las pruebas de login y fuerza bruta permiten enviar
token válido para que CSRF no oculte fallos de otros bloques. No se ejecutó
la batería completa de seguridad ni la de fuerza bruta en este cierre.

### Cierre local y dependencias de integración

Se completó la implementación propia de CSRF, validación de pedidos y
reseñas, y restricciones de subida. Se documentaron los siguientes resultados:

| Caso manual posterior | Resultado |
|---|---|
| Pedido desde un formulario externo | 403 por origen no permitido |
| Login normal del panel | Acceso correcto con cuenta administrativa de prueba; sin captura |
| Cambio de contraseña desde formulario externo | 403 por origen no permitido; respuesta comunicada sin captura, sin comprobación independiente de la contraseña |
| Cantidades −5 y `"abc"` | 400 por datos inválidos |
| Reseña de 50.000 caracteres | 400 por datos inválidos |
| Reseña breve | 201 y visualización en la página |
| Subida HTML | 400 por formato no admitido |
| Subida PNG | 200 y ruta con nombre generado; visualización manual sin captura |
| Pedido legítimo | Respuesta con pedido 47 y cantidades válidas; sin captura ni estado HTTP registrado |

Las capturas y los registros automáticos están enlazados en las secciones
anteriores. Los logs `despues-*` se conservan como registro histórico;
los logs `cierre-*` corresponden a la revisión final de la lista de tareas.

Quedan como dependencias explícitas para la integración:

- **Sesiones:** integrar el ciclo de vida y limpieza de tokens con la
  rotación/expiración e invalidación de sesiones. El token obligatorio en
  login y `SameSite=Lax` ya están implementados y probados; la seguridad
  completa de los identificadores y el cierre de sesión sigue siendo
  responsabilidad del bloque de sesiones.
- **Configuración:** integrar el manejador de errores sin stack traces
  (`VAL-06`) y coordinar las cabeceras y publicación de `/uploads/`.
- **SQLi:** coordinar los cambios compartidos en `pedidos.service.ts` con
  la parametrización de consultas.
- **Verificación integrada:** comprobar las operaciones del sitio y del
  panel afectadas por los cambios compartidos y volver a evaluar el checklist
  global después de integrarlos. Su último resultado registrado es 11/37,
  por lo que no se declara aprobado el proyecto completo.

### Reflexión · Práctica 3: CSRF

En un proyecto real, las operaciones que modifican datos deben exigir un
token vinculado al visitante o a su sesión, también al iniciar sesión. El
navegador debe enviar el token desde la interfaz; `SameSite` y la
comprobación de origen son capas adicionales, no sustitutos. El rechazo
por origen del formulario externo no demuestra por sí solo la validación
del token: las regresiones cubren este control por separado. El ciclo de
vida de los tokens debe integrarse con la expiración e invalidación de
sesiones para que la defensa sea completa.

### Reflexión · Práctica 4: Validación de entrada

Los límites del formulario no reemplazan la validación del servidor: fue
posible enviar cantidades inválidas y reseñas extensas modificando el
cliente. En un proyecto real se comprueban tipos, formatos, longitudes,
rangos e IDs antes de procesar o persistir. Para los archivos, la extensión
no basta: se verifica el contenido PNG, se acota el tamaño y se genera el
nombre en el servidor. Aceptar sólo PNG RGB/RGBA de 8 bits reduce los
formatos admitidos y debe contemplarse al preparar las imágenes.

Una prueba de datos inválidos debe usar un token válido para distinguir
un **400 de validación** de un **403 por CSRF**. Comprobar también una
reseña, un pedido y una imagen válidos permite verificar que los flujos
legítimos siguen funcionando. Se distinguen las capturas, los resultados
manuales sin captura y las pruebas automáticas para no atribuir a cada
evidencia más alcance del que tiene.

---

## Autenticación, sesiones y autorización

**Responsable:** Peralta, Julián
**Fallas:** VUL-13 a VUL-21 e IDOR en pedidos · **OWASP:** A01:2021 — Broken Access Control, A02:2021 — Cryptographic Failures, A07:2021 — Identification and Authentication Failures

> Estado: implementación y pruebas automáticas realizadas sobre una copia local
> del código (Node y PostgreSQL 16, **sin Docker**). **Quedan pendientes** la
> observación manual de cada falla y la verificación en Docker sobre el código
> integrado del grupo. El IDOR está corregido **sólo con acceso estricto**; en
> la configuración Docker de desarrollo sigue abierto.

### Qué es y por qué importa

La **autenticación** comprueba quién es la persona; la **sesión** conserva esa
identidad entre peticiones; la **autorización** decide qué puede hacer. Una
falla en cualquiera de las tres permite usar la aplicación en nombre de otro o
con más permisos de los que corresponden.

| Problema | Consecuencia en la aplicación |
| ----- | ----- |
| **Credenciales mal protegidas** | Claves legibles en la base, intentos ilimitados y mensajes que revelan qué cuentas existen. |
| **Sesiones débiles** | Identificadores adivinables, cookie legible desde JavaScript, sin vencimiento ni cierre real. |
| **Control de acceso ausente** | Un cliente entra al panel, cambia roles y se pueden leer pedidos ajenos. |

### Causa común

El proyecto daba por hecho que el usuario sólo usaría la interfaz de la forma
prevista: comparaba claves en texto plano, confiaba en cualquier cookie `sid`,
exigía sesión sin comprobar el rol y no registraba de quién era cada pedido.

Los números de línea de «Dónde» corresponden al código base recibido, antes de
estas correcciones.

### Cómo preparar la observación manual de la versión vulnerable

La versión corregida convierte las claves a bcrypt, así que la versión
vulnerable necesita su propia base. Estos pasos usan un volumen separado y
conservan los datos de demostración del grupo:

1. En la copia actual: `docker compose down` (**sin** `-v`).
2. En una carpeta aparte con el commit inicial del proyecto:
   `docker compose -p origen-vulnerable up -d --build`.
3. Observar las fallas y guardar las capturas, tapando claves y cookies reales.
4. En esa carpeta: `docker compose -p origen-vulnerable down -v`.
5. En la copia actual: `docker compose up -d`.

---

### VUL-13 · Contraseñas en texto plano

- **Dónde:** `src/inicializar.ts` (líneas 56–63), `src/services/usuarios.service.ts` (líneas 42, 49 y 76–82) y `POST /api/admin/cambiar-contrasena`.
- **Código vulnerable:**

```ts
  [usuario.username, usuario.password, usuario.rol, usuario.nombre]   // carga inicial
  'UPDATE usuarios SET password = $1 WHERE id = $2 RETURNING *'       // cambio de clave
```

- **Cómo se observa:** _pendiente de observación manual._ En la versión
  vulnerable ejecutar
  `docker compose -p origen-vulnerable exec db psql -U postgres -d origen -c "SELECT username, password FROM usuarios"`:
  las claves deben verse legibles.
- **Por qué ocurre:** se guardaba y comparaba el texto tal cual, y las
  consultas con `SELECT *` y `RETURNING *` devolvían la columna `password`.
- **Corrección:** hash bcrypt (costo 12, con salt por usuario) en la carga
  inicial y en todo cambio; las filas antiguas en texto plano se convierten al
  arrancar; las respuestas ya no incluyen el hash:

```ts
  for (const campo of COLUMNAS_PERMITIDAS) {
    const valor = cambios[campo];
    if (valor === undefined) continue;
    valores.push(campo === 'password' ? await hashPassword(String(valor)) : valor);
    campos.push(campo + ' = $' + valores.length);
  }
```

  El cambio de la propia clave además exige la contraseña actual, limita los
  intentos, cierra las otras sesiones y renueva la propia.
- **Decisiones:**
  - Claves nuevas de al menos 8 caracteres y como máximo 72 bytes (bcrypt
    ignora lo que sobra), distintas del nombre de usuario.
  - El código ya no contiene claves de fábrica (**AUTH-13**). Cada cuenta
    inicial usa `CLAVE_INICIAL_<USUARIO>`; si falta, fuera de producción se
    genera una al azar y se muestra una vez en el log. En producción no se crea.
  - Una base existente conserva sus claves anteriores (hasheadas): las claves
    débiles como `admin/admin` hay que cambiarlas.
- **Verificación:** test `las contraseñas NO se guardan en texto plano`,
  pruebas propias de migración y
  [comprobación de migración y producción](evidencia/autenticacion-sesiones/despues-migracion-y-produccion.txt).

---

### VUL-14 · Sin protección contra fuerza bruta

- **Dónde:** `src/routes/auth.routes.ts` (`POST /login`).
- **Código vulnerable:**

```ts
  router.post('/login', async (req, res, next) => {   // sin ningún límite
```

- **Cómo se observa:** _pendiente de observación manual._ Escribir varias veces
  una clave incorrecta en el panel: siempre responde igual y nunca bloquea.
- **Por qué ocurre:** no se contaban los intentos fallidos.
- **Corrección:** `express-rate-limit` en `src/middleware/limites.ts`, por IP y
  por cuenta:

```ts
  router.post('/login', limiteLoginPorIp, limiteLoginPorCuenta, async (req, res, next) => {
```

- **Decisiones:**
  - 5 fallos por cuenta y 20 por IP cada 15 minutos; los ingresos correctos no
    cuentan. Superado el límite responde 429, también con la clave correcta.
  - Se aplica igual a cuentas inexistentes, para no revelar cuáles existen.
  - Costo asumido: alguien puede bloquear 15 minutos la cuenta de otro. Los
    contadores están en memoria y varios clientes pueden compartir IP.
- **Verificación:** bloque `Seguridad · Fuerza bruta` (2/2) y prueba propia de
  bloqueo con cuenta existente e inexistente.

---

### VUL-15 · Cookie de sesión sin protección

- **Dónde:** `src/middleware/sesion.ts` (línea 61).
- **Código vulnerable:**

```ts
  res.cookie('sid', id, { path: '/', sameSite: 'lax' });
```

- **Cómo se observa:** _pendiente de observación manual._ Iniciar sesión y
  revisar DevTools → Application → Cookies: `sid` no tiene `HttpOnly`, y
  `document.cookie` la muestra en la consola.
- **Por qué ocurre:** faltaban `httpOnly` y `secure`. `SameSite=Lax` ya había
  sido agregado en el trabajo de CSRF.
- **Corrección:**

```ts
  {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  }
```

- **Decisiones:** `Secure` se activa sólo en producción porque la práctica local
  usa HTTP. El checklist es un análisis del código; el atributo en producción se
  comprueba con una prueba propia.
- **Verificación:** test `la cookie de sesión lleva HttpOnly, Secure y SameSite`
  y prueba propia de cabecera en ambos entornos.

---

### VUL-16 · Identificador de sesión predecible

- **Dónde:** `src/middleware/sesion.ts` (líneas 48–51).
- **Código vulnerable:**

```ts
  contadorSesiones += 1;
  const id = `sesion_${contadorSesiones}`;
```

- **Cómo se observa:** _pendiente de observación manual._ Iniciar sesión en dos
  navegadores: aparecen valores consecutivos (`sesion_1`, `sesion_2`). Editar
  el valor en DevTools permite tomar la otra sesión.
- **Por qué ocurre:** el identificador es un contador.
- **Corrección:** 256 bits aleatorios y un identificador nuevo en cada login:

```ts
  destruirSesion(req);                          // descarta la sesión anterior
  const id = randomBytes(32).toString('hex');
```

- **Decisiones:** sólo valen identificadores creados por el servidor (contra la
  fijación de sesión). Una cookie mal codificada se ignora en lugar de provocar
  un error 500.
- **Verificación:** test `el identificador de sesión es aleatorio y no predecible`
  y prueba propia de rotación.

---

### VUL-17 · Sesiones que nunca expiran

- **Dónde:** `src/middleware/sesion.ts` (línea 57).
- **Código vulnerable:**

```ts
  expiraEn: null,
```

- **Cómo se observa:** _pendiente de observación manual._ Dejar una sesión
  abierta sin actividad y comprobar que sigue sirviendo; acompañar con la
  captura del código, que no define vencimiento.
- **Por qué ocurre:** no se calculaba ni se controlaba una fecha de expiración.
- **Corrección:** vencimiento por inactividad (30 minutos) y absoluto (8 horas):

```ts
  if (ahora >= sesion.expiraEn) {
    sesiones.delete(id);
    return null;
  }
  sesion.expiraEn = Math.min(ahora + TIEMPO_INACTIVIDAD, sesion.creadaEn + MAX_VIDA);
```

- **Decisiones:** las sesiones vencidas se limpian cada 5 minutos. Siguen en
  memoria: reiniciar la app las cierra todas.
- **Verificación:** pruebas propias de ambos vencimientos, simulando el reloj
  (no se esperó el tiempo real).

---

### VUL-18 · Logout que no invalida la sesión

- **Dónde:** `src/routes/auth.routes.ts` (líneas 69–72).
- **Código vulnerable:**

```ts
  router.post('/logout', (req, res) => {
    res.clearCookie('sid', { path: '/' });
    res.json({ mensaje: 'Sesión cerrada.' });
  });
```

- **Cómo se observa:** _pendiente de observación manual._ Copiar el valor de
  `sid`, cerrar sesión, volver a crear la cookie en DevTools y recargar: la
  sesión sigue activa.
- **Por qué ocurre:** sólo se borraba la cookie del navegador.
- **Corrección:**

```ts
  destruirSesion(req);        // borra la sesión del servidor
  borrarCookieSesion(res);    // borra la cookie
```

- **Decisiones:** la cookie se borra con las mismas opciones con las que se creó.
- **Verificación:** test `el logout invalida la sesión en el servidor`.

---

### VUL-19 · Enumeración de usuarios en el login

- **Dónde:** `src/routes/auth.routes.ts` (líneas 29–40).
- **Código vulnerable:**

```ts
  if (existe) {
    return res.status(401).json({ error: 'La contraseña es incorrecta.' });
  }
  return res.status(401).json({ error: `El usuario "${username}" no existe en el sistema.` });
```

- **Cómo se observa:** _pendiente de observación manual._ Probar un usuario
  inventado y después uno real con clave incorrecta: los mensajes difieren.
- **Por qué ocurre:** se consultaba si la cuenta existía para elegir el mensaje,
  y además se repetía el nombre recibido.
- **Corrección:** una única respuesta y el mismo trabajo de bcrypt exista o no
  el usuario:

```ts
  const coincide = await bcrypt.compare(password, hash ?? (await hashSenuelo));
```

```ts
  return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
```

- **Decisiones:** `username` y `password` deben ser texto. Esta corrección
  resuelve también la parte de **VUL-06** que estaba pendiente en
  `auth.routes.ts`.
- **Verificación:** tests `los mensajes de login son genéricos` y
  `el login NO devuelve HTML sin escapar en el mensaje de error`. La igualdad de
  tiempos de respuesta no se midió.

---

### VUL-20 · Autorización ausente en el panel

- **Dónde:** `src/routes/admin.routes.ts` (línea 34) y `DELETE /api/comentarios/:id`.
- **Código vulnerable:**

```ts
  router.use(requiereSesion);   // exige sesión, pero no rol
```

- **Cómo se observa:** _pendiente de observación manual._ Entrar como `cliente`
  y abrir `/api/admin/usuarios`: se obtiene la lista de usuarios.
- **Por qué ocurre:** `requiereRol` estaba importado pero no se usaba. El borrado
  de reseñas no pedía ni sesión.
- **Corrección:**

```ts
  router.use(requiereSesion);
  router.post('/cambiar-contrasena', limiteCambioPassword, /* ... */);
  router.use(requiereRol(...ROLES_ADMIN));   // protege todo lo que sigue
```

```ts
  router.delete('/:id', requiereSesion, requiereRol(...ROLES_ADMIN), /* ... */);
```

- **Decisiones:** el control va antes de las rutas, así las nuevas quedan
  protegidas. Cada usuario autenticado puede cambiar su propia clave. El rol se
  guarda en la sesión: los cambios hechos desde el panel la cierran, pero uno
  hecho directamente en la base no se refleja hasta un nuevo ingreso.
- **Verificación:** test `un usuario sin rol admin NO puede entrar al panel` y
  pruebas propias con visitante, cliente, mozo y barista.

---

### VUL-21 · Escalada de privilegios

- **Dónde:** `src/routes/admin.routes.ts` (líneas 57–74) y `actualizar` en `usuarios.service.ts`.
- **Código vulnerable:**

```ts
  if (rol !== undefined) cambios.rol = rol;
  // ...
  const usuario = await usuarios.actualizar(req.params.id, cambios);
```

- **Cómo se observa:** _pendiente de observación manual._ Entrar al panel como
  `cliente`, abrir la pestaña Usuarios y cambiar el propio rol a `admin`.
- **Por qué ocurre:** no se comprobaba quién pedía el cambio ni qué rol enviaba.
- **Corrección:** rol admin obligatorio, campos y roles por lista blanca
  (`src/validacion-usuario.ts`) y prohibición de cambiar el propio rol:

```ts
  if (esPropio && cambios.rol !== undefined && cambios.rol !== yo.rol) {
    return res.status(403).json({ error: 'No podés cambiar tu propio rol.' });
  }
```

- **Decisiones:** el usuario modificado pierde sus sesiones abiertas. La clave
  propia sólo se cambia por el endpoint que exige la actual.
- **Verificación:** test `un usuario NO puede cambiar su propio rol a admin`.
  En la línea de base ese test ya pasaba, por lo que no demuestra el control de
  rol; las pruebas propias lo comprueban **con token CSRF válido** (403).

---

### IDOR · Acceso a pedidos ajenos (sin número en la lista)

- **Dónde:** `src/routes/pedidos.routes.ts` (líneas 64–74) y `reportes.routes.ts`.
- **Código vulnerable:**

```ts
  const pedido = await pedidos.obtenerConItems(req.params.id);
  // se devolvía sin comprobar quién preguntaba
```

- **Cómo se observa:** _pendiente de observación manual._ Sin iniciar sesión,
  abrir `/api/pedidos/1` y cambiar el número.
- **Por qué ocurre:** la tabla no registraba el dueño y la ruta no pedía permisos.
- **Corrección:** columna `pedidos.usuario_id`
  (`docker/initdb/03-pedidos-propietario.sql`), dueño tomado de la sesión y
  comprobación al consultar. Un pedido ajeno responde 404:

```ts
  const ajeno =
    accesoEstricto() &&
    !ROLES_PERSONAL.includes(req.usuario!.rol) &&
    pedido?.usuario_id !== req.usuario!.id;
```

- **Decisiones — limitación importante:** los tests funcionales listan y
  consultan pedidos, cambian estados y piden reportes **sin sesión**. Por eso el
  control se activa en producción o con `ACCESO_ESTRICTO=true`. Con el control
  activo, `npm test` da **21/28**
  ([registro](evidencia/autenticacion-sesiones/despues-npm-test-acceso-estricto.txt)).
  Falta acordar con el docente si se pueden adaptar esos tests. Los pedidos sin
  dueño sólo los ve el personal.
- **Verificación:** prueba propia `con acceso estricto impide ver y modificar pedidos ajenos`.

**Matriz de permisos** (\* sólo con acceso estricto):

| Operación | Visitante | Cliente | Barista / mozo | Admin |
| ----- | :---: | :---: | :---: | :---: |
| Catálogo, reseñas y crear pedido | sí | sí | sí | sí |
| Cambiar la propia contraseña | no | sí | sí | sí |
| Resto de `/api/admin` | no | no | no | sí |
| Borrar reseñas | no | no | no | sí |
| Ver pedidos \* | no | propios | todos | todos |
| Cambiar estado de pedidos \* | no | no | sí | sí |
| Ver reportes \* | no | no | no | sí |

---

### Verificación

Resultados reales sobre la copia local. «Antes» es el código base recibido (que
ya incluía los cambios de CSRF y validación); «después» suma las correcciones de
esta sección y las de apoyo indicadas en las dependencias.

| Prueba / Verificación | Antes | Después |
| :--- | :---: | :---: |
| `las contraseñas NO se guardan en texto plano` (VUL-13) | ✘ | ✔ |
| `el login bloquea o limita los intentos repetidos` (VUL-14) | ✘ | ✔ |
| `el login correcto sigue funcionando después de un bloqueo` (VUL-14) | ✔ | ✔ |
| `la cookie de sesión lleva HttpOnly, Secure y SameSite` (VUL-15) | ✘ | ✔ |
| `el identificador de sesión es aleatorio y no predecible` (VUL-16) | ✘ | ✔ |
| `el logout invalida la sesión en el servidor` (VUL-18) | ✘ | ✔ |
| `los mensajes de login son genéricos` (VUL-19) | ✘ | ✔ |
| `el login NO devuelve HTML sin escapar en el mensaje de error` (VUL-06) | ✘ | ✔ |
| `el login NO acepta el bypass con payload SQL` (VUL-01) | ✘ | ✔ |
| `el login NO acepta el payload que comenta la contraseña` (VUL-01) | ✘ | ✔ |
| `un usuario sin rol admin NO puede entrar al panel` (VUL-20) | ✘ | ✔ |
| `un usuario NO puede cambiar su propio rol a admin` (VUL-21) | ✔ | ✔ |
| Pruebas propias de sesiones y permisos | — | 12/12 ✔ |
| `npm test` (funcionales, sin acceso estricto) | 28/28 ✔ | 28/28 ✔ |
| Chequeo de tipos (`tsconfig.json` temporal) | sin errores | sin errores |
| Checklist `AUTH` (controles críticos) | 0/13 | 13/13 ✔ |
| `AUTH-13` y `AUTH-15` (recomendados) | pendientes | ✔ |

El checklist global de la copia local pasa de 11/37 a 27/37 y **sigue fallando**
por controles de otros bloques. Esa copia no incluye todas las correcciones del
grupo, así que no representa el estado integrado.

Registros:
[funcionales antes](evidencia/autenticacion-sesiones/antes-npm-test.txt) ·
[funcionales después](evidencia/autenticacion-sesiones/despues-npm-test.txt) ·
[bloques antes](evidencia/autenticacion-sesiones/antes-test-bloques.txt) ·
[bloques después](evidencia/autenticacion-sesiones/despues-test-bloques.txt) ·
[XSS del login antes](evidencia/autenticacion-sesiones/antes-test-xss-login.txt) ·
[XSS del login después](evidencia/autenticacion-sesiones/despues-test-xss-login.txt) ·
[pruebas propias](evidencia/autenticacion-sesiones/despues-regresiones.txt) ·
[checklist antes](evidencia/autenticacion-sesiones/antes-check-security.txt) ·
[checklist después](evidencia/autenticacion-sesiones/despues-check-security.txt) ·
[tipos antes](evidencia/autenticacion-sesiones/antes-typecheck.txt) ·
[tipos después](evidencia/autenticacion-sesiones/despues-typecheck.txt)

Comandos para repetir la verificación dentro del contenedor:

```sh
npm test
node --import tsx --test --test-concurrency=1 --test-name-pattern="Seguridad · (Autenticación y sesiones|Login|Fuerza bruta)" tests/seguridad.test.ts tests/seguridad-login.test.ts tests/seguridad-fuerza-bruta.test.ts
node --import tsx --test --test-concurrency=1 tests/sesiones-regresion.test.ts tests/permisos-regresion.test.ts
npm run check:security
```

### Dependencias de integración

- **SQLi:** el login queda parametrizado y usa `bcrypt.compare` (VUL-01). Al unir
  `pedidos.service.ts`, conservar la consulta parametrizada de `listar`,
  `listarDeUsuario` y el campo `usuario_id`.
- **XSS:** se modificaron `admin.html` y `admin.js` para pedir la contraseña
  actual y se quitó la lista de claves de prueba del login.
- **CSRF:** el token queda ligado al identificador de sesión. Se comprobó en la
  copia local que, tras el logout, la cookie y el token anteriores reciben 403.
  Siguen pendientes la limpieza en memoria de esos tokens y `Secure` en la cookie
  `csrf_visitante`. El cambio de contraseña ahora exige también la actual.
- **Configuración:** como apoyo se prepararon cambios en `errores.ts` (XSS-02 y
  VAL-06) y `config.ts` (CFG-02), a confirmar y documentar en ese bloque. Con
  HTTPS detrás de un proxy hay que configurar `trust proxy`. Si la app usa
  `origen_app` sobre una base existente, ejecutar el script `03` como `postgres`.

### Reflexión · Autenticación y sesiones

Las contraseñas deben guardarse con un algoritmo lento y con salt, y la sesión
debe ser imposible de adivinar, ilegible para JavaScript, temporal y revocable
desde el servidor. En un proyecto real convendría usar una librería de sesiones
mantenida con almacenamiento persistente, HTTPS obligatorio y un segundo factor
para los administradores, sin cuentas con claves de fábrica.

### Reflexión · Login y fuerza bruta

Un mensaje genérico evita confirmar qué cuentas existen y el límite de intentos
encarece adivinar claves. Ninguna medida alcanza sola: en producción se sumarían
un contador compartido entre instancias, alertas y demoras progresivas, evaluando
que el bloqueo no sirva para dejar afuera a usuarios legítimos.

### Reflexión · Autorización

Iniciar sesión no da derecho a todo. El servidor debe negar por defecto y
comprobar en cada operación el rol y el dueño del dato; ocultar botones en la
interfaz no protege. El dueño de cada registro conviene definirlo desde el diseño
de la base, y cada ruta debe probarse con cada rol.

---

## Configuración / Inyección de comandos

### Hallazgos y riesgos abordados
- **Inyección de comandos en diagnóstico de red (`src/routes/admin.routes.ts`):** El endpoint `POST /api/admin/probar-conexion` concatenaba el `host` recibido en `req.body` dentro de un comando `ping -c 3 ${host}` ejecutado mediante `exec`, permitiendo inyección de comandos del sistema operativo.
- **Endpoint de diagnóstico / depuración (`src/routes/debug.routes.ts` y `src/app.ts`):** Exposición potencial de información interna/entorno o falta de control de acceso/habilitación condicional.
- **Exposición de detalles internos en errores (`src/middleware/errores.ts`):** Riesgo de filtrar `stack` traces o información sensible en respuestas al cliente ante fallos.
- **Cabeceras de seguridad y CSP (`src/app.ts`):** Falta de cabeceras como `X-Content-Type-Options`, `Referrer-Policy` y `Content-Security-Policy` (coordinado con frontend para no romper scripts/estilos/recursos).
- **Base de datos y contenedores (`docker/initdb/02-usuario-aplicacion.sql`, `docker-compose.yml`, `Dockerfile`):** Uso de credenciales/autenticación débiles o de superusuario (`postgres`) en la app, publicación de puertos sin restringir a `127.0.0.1` y ejecución del proceso con privilegios de `root` en el contenedor.

### Correcciones aplicadas
- **Validación por lista blanca y `spawn` sin shell (`src/routes/admin.routes.ts`):** Se valida que `host` sea string y pertenezca a `HOSTS_PERMITIDOS` (respondiendo `400` si no está permitido) y se ejecuta `ping` con `spawn('ping', ['-c', '3', host], { shell: false })`.
- **Restricción de diagnóstico (`src/routes/debug.routes.ts` y `src/app.ts`):** Se protegió el endpoint de diagnóstico, se removió la exposición de datos sensibles del entorno y se condicionó su montaje según configuración.
- **Manejo centralizado de errores (`src/middleware/errores.ts`):** Se registran los detalles del error internamente en el servidor mientras se devuelve una respuesta genérica y segura al cliente, manteniendo `manejadorErrores` al final del pipeline en `src/app.ts`.
- **Cabeceras de seguridad y CSP (`src/app.ts`):** Se configuraron cabeceras de seguridad y `Content-Security-Policy` (y se deshabilitó `x-powered-by`), revisando compatibilidad con el frontend.
- **Mínimos privilegios en PostgreSQL y endurecimiento Docker (`docker/initdb/02-usuario-aplicacion.sql`, `docker-compose.yml`, `Dockerfile`):** Se configuró el rol de aplicación (`origen_app`) con permisos acotados (`CONNECT`, `USAGE` en `public`, `SELECT`/`INSERT`/`UPDATE`/`DELETE` en tablas y `USAGE`/`SELECT` en secuencias), autenticación `scram-sha-256`, binding a `127.0.0.1` en `docker-compose.yml` y usuario no-root (`appuser`) en el `Dockerfile`.

### Verificación y evidencia
- Estado de pruebas y controles ejecutados: *(completar aquí el resultado real de `npm test`, `npm run test:seguridad` y `npm run check:security`, indicando qué pasó y qué quedó pendiente si aplica).*
- Archivos de evidencia asociados: *(agregar rutas si guardaron capturas o salidas en el repo).*