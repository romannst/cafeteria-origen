export function pedidoValido(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  const { mesa, cliente, items } = body as Record<string, unknown>;
  return typeof mesa === 'string' && /^[0-9]{1,10}$/.test(mesa) &&
    typeof cliente === 'string' && cliente.trim().length >= 2 &&
    cliente.length <= 40 &&
    Array.isArray(items) && items.length >= 1 && items.length <= 20 &&
    items.every((item: unknown) => {
      if (!item || typeof item !== 'object') return false;
      const { productoId, cantidad } = item as Record<string, unknown>;
      // Los formularios urlencoded envían números como strings.
      const id = typeof productoId === 'string' && /^[1-9]\d*$/.test(productoId)
        ? Number(productoId) : productoId;
      const n = typeof cantidad === 'string' && /^[1-9]\d*$/.test(cantidad)
        ? Number(cantidad) : cantidad;
      return Number.isSafeInteger(id) && (id as number) > 0 &&
        Number.isSafeInteger(n) && (n as number) >= 1 && (n as number) <= 100;
    });
}

export function comentarioValido(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  const { autor, texto, calificacion } = body as Record<string, unknown>;
  return typeof autor === 'string' && autor.trim().length >= 2 &&
    autor.length <= 40 && typeof texto === 'string' &&
    texto.trim().length >= 3 && texto.length <= 280 &&
    Number.isInteger(calificacion) && (calificacion as number) >= 1 &&
    (calificacion as number) <= 5;
}

export function estadoValido(estado: unknown): estado is string {
  const valoresValidosEstado = ['abierto', 'preparando', 'listo', 'entregado', 'cancelado'];
  return typeof estado === 'string' && valoresValidosEstado.includes(estado);
}
