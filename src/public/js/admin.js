/* =============================================================================
   Cafetería Origen — lógica del panel de administración
   ============================================================================= */
(function () {
  'use strict';

  var API = '/api';
  var usuario = null;
  var productosCache = {};

  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

  function money(valor) {
    return Number(valor || 0).toLocaleString('es-AR', { style: 'currency', currency: 'ARS' });
  }

  // Crea un elemento HTML con su clase y su texto. Usa textContent,
  // así que el texto nunca se interpreta como HTML (no hay XSS).
  function crearEl(tag, clase, texto) {
    var nodo = document.createElement(tag);
    if (clase) nodo.className = clase;
    if (texto != null) nodo.textContent = String(texto);
    return nodo;
  }

  // Llena una <table> con encabezado y filas. Cada celda puede ser texto
  // (se inserta con textContent) o un nodo ya armado (un select, un botón).
  function llenarTabla(tabla, columnas, filas) {
    var trHead = crearEl('tr');
    columnas.forEach(function (col) {
      trHead.append(crearEl('th', col.clase, col.titulo));
    });
    var thead = crearEl('thead');
    thead.append(trHead);

    var tbody = crearEl('tbody');
    filas.forEach(function (celdas) {
      var tr = crearEl('tr');
      celdas.forEach(function (celda, i) {
        var td = crearEl('td', columnas[i].clase);
        if (celda instanceof Node) td.append(celda);
        else td.textContent = celda == null ? '' : String(celda);
        tr.append(td);
      });
      tbody.append(tr);
    });

    tabla.replaceChildren(thead, tbody);
  }

  // <select> con opciones fijas; marca como elegida la opción actual.
  function crearSelect(clase, atributo, id, opciones, actual) {
    var sel = crearEl('select', clase);
    sel.setAttribute(atributo, id);
    opciones.forEach(function (op) {
      var o = crearEl('option', null, op);
      o.value = op;
      if (op === actual) o.selected = true;
      sel.append(o);
    });
    return sel;
  }

  // Tarjetas de indicadores (KPI): etiqueta + valor, ambos como texto.
  function renderKpis(contenedor, kpis) {
    contenedor.replaceChildren(...kpis.map(function (k) {
      var div = crearEl('div', 'kpi');
      div.append(crearEl('div', 'kpi-label', k.label), crearEl('div', 'kpi-value', k.value));
      return div;
    }));
  }

  function api(url, opciones) {
    var config = Object.assign({}, opciones || {});
    var metodo = (config.method || 'GET').toUpperCase();
    var preparar = ['GET', 'HEAD', 'OPTIONS'].indexOf(metodo) === -1 && url !== '/auth/login'
      ? fetch(API + '/csrf-token').then(function (res) {
        if (!res.ok) throw new Error('No se pudo obtener el token CSRF.');
        return res.json();
      }).then(function (data) {
        config.headers = Object.assign({}, config.headers || {}, { 'X-CSRF-Token': data.token });
      })
      : Promise.resolve();
    return preparar.then(function () { return fetch(API + url, config); }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        return { ok: res.ok, status: res.status, data: data };
      });
    });
  }

  function postJSON(url, cuerpo) {
    return api(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cuerpo || {}),
    });
  }

  function putJSON(url, cuerpo) {
    return api(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cuerpo || {}),
    });
  }

  function patchJSON(url, cuerpo) {
    return api(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cuerpo || {}),
    });
  }

  function feedback(el, mensaje, ok) {
    el.className = 'form-feedback ' + (ok ? 'is-ok' : 'is-error');
    el.textContent = mensaje;
  }

  /* ------------------------------------------------------------------ login */
  function iniciarSesion(evento) {
    evento.preventDefault();
    var caja = $('#login-feedback');
    caja.className = 'form-feedback';

    postJSON('/auth/login', {
      username: $('#login-usuario').value,
      password: $('#login-password').value,
    }).then(function (resp) {
      if (!resp.ok) {
        feedback(caja, 'No pudimos iniciar sesión: ' + (resp.data.error || 'error desconocido'), false);
        return;
      }
      usuario = resp.data.usuario;
      mostrarPanel();
    });
  }

  function cerrarSesion() {
    postJSON('/auth/logout', {}).then(function () {
      usuario = null;
      $('#vista-login').hidden = false;
      $('#vista-panel').hidden = true;
      $('#admin-user').replaceChildren();
    });
  }

  function mostrarPanel() {
    $('#vista-login').hidden = true;
    $('#vista-panel').hidden = false;
    $('#admin-user').replaceChildren(
      'Sesión de ',
      crearEl('strong', null, usuario.nombre),
      ' · rol: ',
      crearEl('strong', null, usuario.rol)
    );
    $('#panel-bienvenida').textContent = 'Hola, ' + usuario.nombre;
    cargarTodo();
  }

  function cargarTodo() {
    cargarResumen();
    cargarPedidos();
    cargarProductos();
    cargarReportes();
    cargarUsuarios();
  }

  /* ---------------------------------------------------------------- resumen */
  function cargarResumen() {
    api('/reportes/facturacion').then(function (f) {
      api('/reportes/mas-vendido').then(function (m) {
        api('/reportes/cantidad-vendida').then(function (c) {
          var mas = m.data.producto;
          var kpis = [
            { label: 'Facturación total', value: money(f.data.facturado) },
            { label: 'Pedidos registrados', value: f.data.pedidos },
            {
              label: 'Producto más vendido',
              value: mas ? mas.nombre : '—',
            },
            {
              label: 'Unidades por tipo',
              value: Object.keys(c.data.cantidadVendida || {})
                .map(function (k) { return k + ': ' + c.data.cantidadVendida[k]; })
                .join(' · ') || '—',
            },
          ];

          renderKpis($('#kpis'), kpis);
        });
      });
    });
  }

  /* --------------------------------------------------------------- pedidos */
  function tablaPedidos(tabla, filas, conAcciones) {
    if (!filas || filas.length === 0) {
      tabla.replaceChildren(crearEl('caption', 'empty', 'No hay pedidos.'));
      return;
    }

    var columnas = [
      { titulo: '#' }, { titulo: 'Mesa' }, { titulo: 'Cliente' }, { titulo: 'Estado' },
      { titulo: 'Total', clase: 'num' }, { titulo: 'Fecha' },
    ];
    if (conAcciones) columnas.push({ titulo: 'Acciones' });

    llenarTabla(tabla, columnas, filas.map(function (p) {
      var celdas = [
        p.id,
        p.mesa,
        p.cliente,
        crearEl('span', 'badge badge-' + p.estado, p.estado),
        money(p.total),
        new Date(p.creado_en).toLocaleString('es-AR'),
      ];
      if (conAcciones) {
        celdas.push(crearSelect('sel-estado', 'data-pedido', p.id,
          ['abierto', 'preparando', 'listo', 'entregado'], p.estado));
      }
      return celdas;
    }));
  }

  function cargarPedidos() {
    api('/pedidos').then(function (resp) {
      var pedidos = resp.data.pedidos || [];
      tablaPedidos($('#tabla-pedidos'), pedidos, true);
      tablaPedidos($('#tabla-ultimos'), pedidos.slice(0, 5), false);
    });
  }

  function cambiarEstado(evento) {
    var select = evento.target.closest('.sel-estado');
    if (!select) return;
    var id = select.getAttribute('data-pedido');
    patchJSON('/pedidos/' + id + '/estado', { estado: select.value }).then(function (resp) {
      if (!resp.ok) {
        alert('No se pudo cambiar el estado: ' + (resp.data.error || 'error'));
      }
      cargarPedidos();
    });
  }

  /* ------------------------------------------------------------- productos */
  function cargarProductos() {
    api('/productos').then(function (resp) {
      var productos = resp.data.productos || [];
      productosCache = {};

      var columnas = [
        { titulo: '#' }, { titulo: 'Nombre' }, { titulo: 'Tipo' }, { titulo: 'Origen' },
        { titulo: 'Precio', clase: 'num' }, { titulo: 'Acciones' },
      ];

      llenarTabla($('#tabla-productos'), columnas, productos.map(function (p) {
        productosCache[p.id] = p;
        var boton = crearEl('button', 'link-danger', 'Borrar');
        boton.dataset.borrar = p.id;
        return [p.id, p.nombre, p.tipo, p.variedad || '—', money(p.precio), boton];
      }));
    });
  }

  function guardarProducto(evento) {
    evento.preventDefault();
    var caja = $('#producto-feedback');
    var id = $('#producto-id').value;

    var cuerpo = {
      nombre: $('#p-nombre').value,
      tipo: $('#p-tipo').value,
      variedad: $('#p-variedad').value || null,
      tamano: $('#p-tamano').value || null,
      gramos: $('#p-gramos').value ? Number($('#p-gramos').value) : null,
      precio_base: Number($('#p-precio-base').value || 0),
      precio_por_gramo: Number($('#p-precio-gramo').value || 0),
      descripcion: $('#p-descripcion').value,
    };

    var peticion = id ? putJSON('/admin/productos/' + id, cuerpo) : postJSON('/admin/productos', cuerpo);

    peticion.then(function (resp) {
      if (!resp.ok) {
        feedback(caja, 'No se pudo guardar: ' + (resp.data.error || 'error desconocido'), false);
        return;
      }
      feedback(caja, 'Producto guardado correctamente.', true);
      $('#form-producto').reset();
      $('#producto-id').value = '';
      cargarProductos();
    });
  }

  function borrarProducto(evento) {
    var btn = evento.target.closest('[data-borrar]');
    if (!btn) return;
    var id = btn.getAttribute('data-borrar');
    if (!confirm('¿Borrar el producto #' + id + '?')) return;

    api('/admin/productos/' + id, { method: 'DELETE' }).then(function (resp) {
      if (!resp.ok) alert('No se pudo borrar: ' + (resp.data.error || 'error'));
      cargarProductos();
    });
  }

  function limpiarFormularioProducto() {
    $('#form-producto').reset();
    $('#producto-id').value = '';
  }

  /* ---------------------------------------------------------------- upload */
  function subirArchivo(evento) {
    evento.preventDefault();
    var caja = $('#upload-feedback');
    var input = $('#archivo-subida');
    if (!input.files || !input.files[0]) {
      feedback(caja, 'Elegí un archivo primero.', false);
      return;
    }

    var archivo = input.files[0];
    var lector = new FileReader();

    lector.onload = function () {
      var base64 = String(lector.result).split(',')[1] || '';
      postJSON('/admin/subir-archivo', {
        nombre: archivo.name,
        contenidoBase64: base64,
      }).then(function (resp) {
        if (!resp.ok) {
          feedback(caja, 'No se pudo subir: ' + (resp.data.error || 'error desconocido'), false);
          return;
        }
        feedback(caja, 'Archivo subido a ' + resp.data.url, true);
      });
    };

    lector.readAsDataURL(archivo);
  }

  /* -------------------------------------------------------------- reportes */
  function cargarReportes() {
    api('/reportes/facturacion').then(function (f) {
      api('/reportes/ticket-promedio').then(function (t) {
        api('/reportes/mas-vendido').then(function (m) {
          var mas = m.data.producto;
          var kpis = [
            { label: 'Facturación', value: money(f.data.facturado) },
            { label: 'Pedidos', value: f.data.pedidos },
            { label: 'Ticket promedio', value: money(t.data.promedio) },
            { label: 'Más vendido', value: mas ? mas.nombre + ' (' + mas.unidades + ')' : '—' },
          ];
          renderKpis($('#kpis-reportes'), kpis);
        });
      });
    });
  }

  function consultarVentas() {
    var caja = $('#reporte-feedback');
    var variedad = $('#reporte-variedad').value;

    api('/reportes/ventas-por-variedad?variedad=' + encodeURIComponent(variedad)).then(function (resp) {
      if (!resp.ok) {
        feedback(caja, 'Error: ' + (resp.data.error || 'desconocido'), false);
        $('#tabla-ventas').replaceChildren();
        return;
      }
      var ventas = resp.data.ventas || [];
      var columnas = [
        { titulo: 'Origen' }, { titulo: 'Producto' },
        { titulo: 'Unidades', clase: 'num' }, { titulo: 'Total', clase: 'num' },
      ];
      llenarTabla($('#tabla-ventas'), columnas, ventas.map(function (v) {
        return [v.variedad, v.nombre, v.unidades, money(v.total)];
      }));
      feedback(caja, 'Consulta realizada.', true);
    });
  }

  /* -------------------------------------------------------------- usuarios */
  function cargarUsuarios() {
    api('/admin/usuarios').then(function (resp) {
      var usuarios = resp.data.usuarios || [];
      var columnas = [
        { titulo: '#' }, { titulo: 'Usuario' }, { titulo: 'Nombre' }, { titulo: 'Rol' }, { titulo: 'Acciones' },
      ];
      llenarTabla($('#tabla-usuarios'), columnas, usuarios.map(function (u) {
        return [
          u.id,
          u.username,
          u.nombre,
          crearEl('span', 'badge' + (u.rol === 'admin' ? ' badge-admin' : ''), u.rol),
          crearSelect('sel-rol', 'data-usuario', u.id, ['cliente', 'mozo', 'barista', 'admin'], u.rol),
        ];
      }));
    });
  }

  function cambiarRol(evento) {
    var select = evento.target.closest('.sel-rol');
    if (!select) return;
    var id = select.getAttribute('data-usuario');

    putJSON('/admin/usuarios/' + id, { rol: select.value }).then(function (resp) {
      if (!resp.ok) alert('No se pudo actualizar: ' + (resp.data.error || 'error'));
      cargarUsuarios();
    });
  }

  function cambiarPassword(evento) {
    evento.preventDefault();
    var caja = $('#password-feedback');
    postJSON('/admin/cambiar-contrasena', { nueva: $('#nueva-password').value }).then(function (resp) {
      if (!resp.ok) {
        feedback(caja, 'No se pudo cambiar: ' + (resp.data.error || 'error desconocido'), false);
        return;
      }
      feedback(caja, 'Contraseña actualizada.', true);
      $('#nueva-password').value = '';
    });
  }

  /* ----------------------------------------------------------- herramientas */
  function probarConexion(evento) {
    evento.preventDefault();
    var salida = $('#salida-conexion');
    salida.textContent = 'Probando…';

    postJSON('/admin/probar-conexion', { host: $('#conexion-host').value }).then(function (resp) {
      if (!resp.ok) {
        salida.textContent = 'Error: ' + (resp.data.error || 'desconocido');
        return;
      }
      salida.textContent =
        '$ ' + resp.data.comando + '\n\n' +
        (resp.data.salida || '') +
        (resp.data.error ? '\n[stderr]\n' + resp.data.error : '');
    });
  }

  function verDiagnostico() {
    var salida = $('#salida-diagnostico');
    salida.textContent = 'Cargando…';
    api('/_diagnostico').then(function (resp) {
      salida.textContent = JSON.stringify(resp.data, null, 2);
    });
  }

  /* ------------------------------------------------------------------ tabs */
  function activarTab(evento) {
    var tab = evento.target.closest('.tab');
    if (!tab) return;
    var vista = tab.getAttribute('data-vista');
    $$('.tab').forEach(function (t) { t.classList.remove('is-active'); });
    tab.classList.add('is-active');
    $$('.tab-panel').forEach(function (p) {
      p.classList.toggle('is-active', p.getAttribute('data-panel') === vista);
    });
  }

  /* ------------------------------------------------------------------ init */
  function init() {
    // El parámetro ?vista= de la URL lo controla cualquiera que arme el link:
    // sólo se acepta si está en la lista blanca de vistas y se muestra con
    // textContent. Cualquier otro valor se ignora.
    var VISTAS = ['resumen', 'pedidos', 'productos', 'reportes', 'usuarios', 'herramientas'];
    var objetivo = new URLSearchParams(window.location.search).get('vista');
    if (objetivo && VISTAS.indexOf(objetivo) !== -1) {
      $('#panel-bienvenida').textContent = 'Panel ' + objetivo;
    }

    $('#form-login').addEventListener('submit', iniciarSesion);
    $('#btn-logout').addEventListener('click', cerrarSesion);
    $('#btn-refrescar').addEventListener('click', cargarTodo);
    $('#tabs').addEventListener('click', activarTab);
    $('#tabla-pedidos').addEventListener('change', cambiarEstado);
    $('#tabla-productos').addEventListener('click', borrarProducto);
    $('#form-producto').addEventListener('submit', guardarProducto);
    $('#btn-limpiar-producto').addEventListener('click', limpiarFormularioProducto);
    $('#form-upload').addEventListener('submit', subirArchivo);
    $('#form-password').addEventListener('submit', cambiarPassword);
    $('#btn-reporte-variedad').addEventListener('click', consultarVentas);
    $('#tabla-usuarios').addEventListener('change', cambiarRol);
    $('#form-conexion').addEventListener('submit', probarConexion);
    $('#btn-diagnostico').addEventListener('click', verDiagnostico);

    // ¿Ya hay sesión?
    api('/auth/yo').then(function (resp) {
      if (resp.ok) {
        usuario = resp.data.usuario;
        mostrarPanel();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
