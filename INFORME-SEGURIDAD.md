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