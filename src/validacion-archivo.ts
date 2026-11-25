import path from 'path';
import { inflateSync } from 'zlib';

const FIRMA = Buffer.from('89504e470d0a1a0a', 'hex');
export const MAX_BYTES = 2 * 1024 * 1024;

function crc32(datos: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of datos) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Acepta únicamente PNG completos y sin bytes adicionales después de IEND. */
function pngValido(datos: Buffer): boolean {
  if (datos.length < 57 || !datos.subarray(0, 8).equals(FIRMA)) return false;
  let pos = 8;
  let ihdr = false;
  const idats: Buffer[] = [];
  let ancho = 0;
  let alto = 0;
  let canales = 0;
  while (pos + 12 <= datos.length) {
    const longitud = datos.readUInt32BE(pos);
    if (longitud > MAX_BYTES || pos + 12 + longitud > datos.length) return false;
    const tipo = datos.toString('ascii', pos + 4, pos + 8);
    if (!/^[A-Za-z]{4}$/.test(tipo)) return false;
    const fin = pos + 8 + longitud;
    if (crc32(datos.subarray(pos + 4, fin)) !== datos.readUInt32BE(fin)) return false;
    if (!ihdr) {
      if (tipo !== 'IHDR' || longitud !== 13) return false;
      ancho = datos.readUInt32BE(pos + 8);
      alto = datos.readUInt32BE(pos + 12);
      if (!ancho || !alto || ancho > 4096 || alto > 4096) return false;
      const color = datos[pos + 17];
      canales = color === 2 ? 3 : color === 6 ? 4 : 0;
      if (datos[pos + 16] !== 8 || !canales ||
        datos[pos + 18] !== 0 || datos[pos + 19] !== 0 || datos[pos + 20] !== 0 ||
        alto * (1 + ancho * canales) > 16 * 1024 * 1024) return false;
      ihdr = true;
    } else if (tipo === 'IDAT') {
      idats.push(datos.subarray(pos + 8, fin));
    } else if (tipo === 'IEND') {
      if (longitud !== 0 || !idats.length || fin + 4 !== datos.length) return false;
      const linea = 1 + ancho * canales;
      const esperado = alto * linea;
      try {
        const pixeles = inflateSync(Buffer.concat(idats), { maxOutputLength: esperado + 1 });
        if (pixeles.length !== esperado) return false;
        for (let y = 0; y < alto; y++) {
          if (pixeles[y * linea] > 4) return false;
        }
        return true;
      } catch {
        return false;
      }
    } else if (!['PLTE', 'tRNS', 'gAMA', 'sRGB', 'pHYs', 'cHRM', 'iCCP'].includes(tipo)) {
      return false;
    }
    pos = fin + 4;
  }
  return false;
}

export function imagenPng(nombre: unknown, contenido: unknown): Buffer | null {
  if (typeof nombre !== 'string' || path.basename(nombre) !== nombre ||
    path.win32.basename(nombre) !== nombre || nombre.length > 120 ||
    path.extname(nombre).toLowerCase() !== '.png' ||
    typeof contenido !== 'string' || !contenido.length ||
    contenido.length > Math.ceil(MAX_BYTES / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(contenido)) {
    return null;
  }
  const datos = Buffer.from(contenido, 'base64');
  return datos.length <= MAX_BYTES && pngValido(datos) ? datos : null;
}
