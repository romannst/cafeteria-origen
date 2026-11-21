/* =============================================================================
   Cafetería Origen — lógica del sitio público
   ============================================================================= */
(function () {
  'use strict';

  var API = '/api';
  var CARRITO_KEY = 'origen.carrito';

  var estado = {
    tipo: '',
    variedad: '',
    q: '',
    carrito: cargarCarrito(),
  };

  /* ---------------------------------------------------------------- utils */
  function $(sel) { return document.querySelector(sel); }

  function money(valor) {
    var n = Number(valor || 0);
    return n.toLocaleString('es-AR', { style: 'currency', currency: 'ARS' });
  }

  // Crea un elemento HTML con su clase y su texto. Usa textContent,
  // así que el texto nunca se interpreta como HTML (no hay XSS).
  function crearEl(tag, clase, texto) {
    var nodo = document.createElement(tag);
    if (clase) nodo.className = clase;
    if (texto != null) nodo.textContent = String(texto);
    return nodo;
  }

  // Botón del carrito con su acción (mas / menos / quitar) y el índice del item.
  function botonCarrito(accion, indice, texto, clase) {
    var b = crearEl('button', clase, texto);
    b.type = 'button';
    b.dataset.acc = accion;
    b.dataset.i = indice;
    return b;
  }

  function api(url, opciones) {
    return fetch(API + url, opciones).then(function (res) {
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

  function guardarCarrito() {
    try {
      localStorage.setItem(CARRITO_KEY, JSON.stringify(estado.carrito));
    } catch (e) { /* almacenamiento no disponible */ }
  }

  function cargarCarrito() {
    try {
      return JSON.parse(localStorage.getItem(CARRITO_KEY)) || [];
    } catch (e) {
      return [];
    }
  }



  /* ------------------------------------------------------------- catálogo */
  function urlCatalogo() {
    var params = new URLSearchParams();
    if (estado.tipo) params.set('tipo', estado.tipo);
    if (estado.variedad) params.set('variedad', estado.variedad);
    if (estado.q) params.set('q', estado.q);
    var s = params.toString();
    return '/productos' + (s ? '?' + s : '');
  }

  function cargarProductos() {
    return api(urlCatalogo()).then(function (resp) {
      if (!resp.ok) {
        renderErrorProductos(resp.data && resp.data.error);
        return;
      }
      renderProductos(resp.data.productos);
      renderResultado(resp.data.filtros, resp.data.total);
    });
  }

  function renderProductos(productos) {
    var grid = $('#productos-grid');

    if (!productos || productos.length === 0) {
      grid.replaceChildren(crearEl('p', 'empty', 'No encontramos productos con esos filtros.'));
      return;
    }

    // Cada tarjeta se arma con nodos: nombre, descripción y etiquetas
    // vienen de la base y se insertan como texto.
    var tarjetas = productos.map(function (p) {
      window.__productos[p.id] = p;

      var top = crearEl('div', 'product-top');
      top.append(
        crearEl('h3', 'product-name', p.nombre),
        crearEl('span', 'product-price', money(p.precio))
      );

      var tags = crearEl('div', 'product-tags');
      tags.append(crearEl('span', 'tag', p.tipo));
      if (p.variedad) tags.append(crearEl('span', 'tag tag-origen', p.variedad));
      if (p.tamano) tags.append(crearEl('span', 'tag', p.tamano));

      var boton = crearEl('button', 'btn btn-ghost btn-agregar', 'Agregar');
      boton.dataset.id = p.id;

      var card = crearEl('article', 'product-card');
      card.append(top, tags, crearEl('p', 'product-desc', p.descripcion), boton);
      return card;
    });

    grid.replaceChildren(...tarjetas);
  }

  function renderResultado(filtros, total) {
    var el = $('#resultado-busqueda');

    if (filtros && filtros.q) {
      // El texto buscado va dentro de un <strong> creado con textContent:
      // se muestra como texto aunque contenga etiquetas HTML.
      el.replaceChildren(
        'Resultados para ',
        crearEl('strong', null, filtros.q),
        ' — ' + total + ' producto(s)'
      );
    } else {
      el.textContent = total + ' producto(s) en el menú';
    }
  }

  function renderErrorProductos(mensaje) {
    $('#productos-grid').replaceChildren(
      crearEl('p', 'empty', 'No se pudo cargar el menú: ' + (mensaje || 'error desconocido'))
    );
  }

  /* --------------------------------------------------------------- carrito */
  function agregarAlCarrito(productoId) {
    var existente = null;
    for (var i = 0; i < estado.carrito.length; i++) {
      if (String(estado.carrito[i].id) === String(productoId)) existente = estado.carrito[i];
    }
    if (existente) {
      existente.cantidad += 1;
    } else {
      estado.carrito.push({
        id: productoId,
        nombre: window.__productos[productoId] ? window.__productos[productoId].nombre : 'Producto',
        precio: window.__productos[productoId] ? window.__productos[productoId].precio : 0,
        cantidad: 1,
      });
    }
    guardarCarrito();
    renderCarrito();
  }

  function cambiarCantidad(indice, delta) {
    var item = estado.carrito[indice];
    if (!item) return;
    item.cantidad += delta;
    if (item.cantidad <= 0) estado.carrito.splice(indice, 1);
    guardarCarrito();
    renderCarrito();
  }

  function quitarDelCarrito(indice) {
    estado.carrito.splice(indice, 1);
    guardarCarrito();
    renderCarrito();
  }

  function renderCarrito() {
    var cont = $('#carrito');
    var lista = $('#resumen-carrito');
    var total = 0;

    if (estado.carrito.length === 0) {
      cont.replaceChildren(crearEl('p', 'empty', 'El carrito está vacío.'));
      lista.replaceChildren();
      $('#resumen-total').textContent = money(0);
      return;
    }

    var filas = estado.carrito.map(function (item, i) {
      var subtotal = item.precio * item.cantidad;
      total += subtotal;

      var info = crearEl('div');
      info.append(
        crearEl('div', 'cart-item-name', item.nombre),
        crearEl('div', 'cart-item-meta', money(item.precio) + ' c/u')
      );

      var qty = crearEl('div', 'qty-control');
      qty.append(
        botonCarrito('menos', i, '−'),
        crearEl('span', null, item.cantidad),
        botonCarrito('mas', i, '+')
      );

      var precio = crearEl('div');
      precio.append(
        crearEl('div', 'cart-item-price', money(subtotal)),
        botonCarrito('quitar', i, 'Quitar', 'link-danger')
      );

      var fila = crearEl('div', 'cart-item');
      fila.append(info, qty, precio);
      return fila;
    });
    cont.replaceChildren(...filas);

    var items = estado.carrito.map(function (item) {
      var li = crearEl('li');
      li.append(
        crearEl('span', null, item.nombre + ' × ' + item.cantidad),
        crearEl('span', null, money(item.precio * item.cantidad))
      );
      return li;
    });
    lista.replaceChildren(...items);

    $('#resumen-total').textContent = money(total);
  }

  /* ---------------------------------------------------------------- pedidos */
  function enviarPedido(evento) {
    evento.preventDefault();
    var feedback = $('#pedido-feedback');
    feedback.className = 'form-feedback';
    feedback.textContent = 'Enviando…';

    postJSON('/pedidos', {
      mesa: $('#pedido-mesa').value,
      cliente: $('#pedido-cliente').value,
      items: estado.carrito.map(function (item) {
        return { productoId: item.id, cantidad: item.cantidad };
      }),
    }).then(function (resp) {
      if (!resp.ok) {
        feedback.className = 'form-feedback is-error';
        feedback.textContent = 'No pudimos enviar el pedido: ' + (resp.data.error || 'error desconocido');
        return;
      }
      feedback.className = 'form-feedback is-ok';
      feedback.textContent = '¡Pedido #' + resp.data.id + ' recibido! Total ' + money(resp.data.total) +
        '. Te atendemos en la mesa ' + resp.data.mesa + '.';
      estado.carrito = [];
      guardarCarrito();
      renderCarrito();
      $('#form-pedido').reset();
    }).catch(function () {
      feedback.className = 'form-feedback is-error';
      feedback.textContent = 'Error de conexión con el servidor.';
    });
  }

  /* --------------------------------------------------------------- reseñas */
  function cargarReseñas() {
    return api('/comentarios').then(function (resp) {
      var cont = $('#lista-resenas');
      if (!resp.ok || !resp.data.comentarios || resp.data.comentarios.length === 0) {
        cont.replaceChildren(crearEl('p', 'empty', 'Todavía no hay reseñas. ¡Sé el primero!'));
        return;
      }

      // Cada reseña se arma nodo por nodo. El autor y el texto vienen de la
      // base (los escribió cualquier visitante), por eso van con textContent:
      // un <script> guardado se muestra como texto y no se ejecuta.
      var articulos = resp.data.comentarios.map(function (c) {
        // La calificación se limita a un número entre 0 y 5.
        var n = Math.min(5, Math.max(0, Math.floor(Number(c.calificacion) || 0)));

        var cabecera = crearEl('div', 'review-head');
        cabecera.append(
          crearEl('span', 'review-author', c.autor),
          crearEl('span', 'review-stars', '★'.repeat(n))
        );

        var articulo = crearEl('article', 'review');
        articulo.append(cabecera, crearEl('p', 'review-text', c.texto));
        return articulo;
      });

      cont.replaceChildren(...articulos);
    });
  }
  
  function enviarReseña(evento) {
    evento.preventDefault();
    var feedback = $('#resena-feedback');
    feedback.className = 'form-feedback';
    feedback.textContent = 'Publicando…';

    postJSON('/comentarios', {
      autor: $('#resena-autor').value,
      texto: $('#resena-texto').value,
      calificacion: Number($('#resena-calificacion').value),
    }).then(function (resp) {
      if (!resp.ok) {
        feedback.className = 'form-feedback is-error';
        feedback.textContent = 'No se pudo publicar: ' + (resp.data.error || 'error desconocido');
        return;
      }
      feedback.className = 'form-feedback is-ok';
      feedback.textContent = '¡Gracias por tu reseña!';
      $('#form-resena').reset();
      cargarReseñas();
    });
  }

  /* ------------------------------------------------------------- listeners */
  function init() {
    window.__productos = {};

    // Filtros
    document.querySelectorAll('.chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        document.querySelectorAll('.chip').forEach(function (c) { c.classList.remove('is-active'); });
        chip.classList.add('is-active');
        estado.tipo = chip.getAttribute('data-tipo');
        cargarProductos();
      });
    });

    $('#filtro-variedad').addEventListener('change', function (e) {
      estado.variedad = e.target.value;
      cargarProductos();
    });

    var temporizador = null;
    $('#filtro-busqueda').addEventListener('input', function (e) {
      estado.q = e.target.value;
      clearTimeout(temporizador);
      temporizador = setTimeout(cargarProductos, 250);
    });

    // Carrito (delegación de eventos)
    $('#productos-grid').addEventListener('click', function (e) {
      var btn = e.target.closest('.btn-agregar');
      if (!btn) return;
      agregarAlCarrito(btn.getAttribute('data-id'));
    });

    $('#carrito').addEventListener('click', function (e) {
      var btn = e.target.closest('button');
      if (!btn) return;
      var i = Number(btn.getAttribute('data-i'));
      var accion = btn.getAttribute('data-acc');
      if (accion === 'mas') cambiarCantidad(i, 1);
      else if (accion === 'menos') cambiarCantidad(i, -1);
      else if (accion === 'quitar') quitarDelCarrito(i);
    });

    $('#form-pedido').addEventListener('submit', enviarPedido);
    $('#form-resena').addEventListener('submit', enviarReseña);

    // Carga inicial
    api(urlCatalogo()).then(function (resp) {
      if (resp.ok) {
        (resp.data.productos || []).forEach(function (p) { window.__productos[p.id] = p; });
        renderProductos(resp.data.productos);
        renderResultado(resp.data.filtros, resp.data.total);
      } else {
        renderErrorProductos(resp.data.error);
      }
    });
    cargarReseñas();
    renderCarrito();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
