import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import fs from 'fs';
import path from 'path';
import { deflateSync } from 'zlib';
import { randomUUID } from 'crypto';
import config from '../src/config';
import { agente, borrarUsuarioDePrueba, crearUsuarioDePrueba, postConToken, prepararBase } from './helpers';

const USUARIO = 'sec_upload_roman';
const creados: string[] = [];

function crc32(datos: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of datos) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(tipo: string, contenido: Buffer): Buffer {
  const longitud = Buffer.alloc(4);
  longitud.writeUInt32BE(contenido.length);
  const datos = Buffer.concat([Buffer.from(tipo), contenido]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(datos));
  return Buffer.concat([longitud, datos, crc]);
}

function pngMinimo(): string {
  const ihdr = Buffer.from('00000001000000010806000000', 'hex');
  return Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(Buffer.from([0, 255, 0, 0, 255]))),
    chunk('IEND', Buffer.alloc(0)),
  ]).toString('base64');
}

describe('Subidas con sesión y token válidos', () => {
  before(async () => {
    await prepararBase();
    await crearUsuarioDePrueba(USUARIO, 'Clave_temporal_regresion!', 'admin');
  });
  after(async () => {
    for (const nombre of creados) {
      if (/^[a-f0-9-]{36}\.png$/.test(nombre)) {
        fs.rmSync(path.join(config.uploadsDir, nombre));
      }
    }
    await borrarUsuarioDePrueba(USUARIO);
  });

  it('rechaza HTML y rutas manipuladas antes de escribir', async () => {
    const http = agente();
    const login = await postConToken(http, '/api/auth/login', {
      username: USUARIO, password: 'Clave_temporal_regresion!',
    });
    assert.equal(login.status, 200);
    for (const nombre of ['prueba.html', '../../fuera.png']) {
      const res = await postConToken(http, '/api/admin/subir-archivo', {
        nombre, contenidoBase64: Buffer.from('<script>prueba</script>').toString('base64'),
      });
      assert.equal(res.status, 400);
    }
    const traversal = await postConToken(http, '/api/admin/subir-archivo', {
      nombre: '../../foto.png', contenidoBase64: pngMinimo(),
    });
    assert.equal(traversal.status, 400);
    const excedido = await postConToken(http, '/api/admin/subir-archivo', {
      nombre: 'grande.png',
      contenidoBase64: Buffer.alloc(2 * 1024 * 1024 + 1).toString('base64'),
    });
    assert.equal(excedido.status, 400);
  });

  it('acepta PNG válido con nombre aleatorio y sirve la imagen', async () => {
    const http = agente();
    const login = await postConToken(http, '/api/auth/login', {
      username: USUARIO, password: 'Clave_temporal_regresion!',
    });
    assert.equal(login.status, 200);
    const res = await postConToken(http, '/api/admin/subir-archivo', {
      nombre: 'foto.png', contenidoBase64: pngMinimo(),
    });
    assert.equal(res.status, 200);
    const nombre = path.basename(res.body.url || '');
    assert.match(nombre, /^[a-f0-9-]{36}\.png$/);
    creados.push(nombre);
    const imagen = await http.get(res.body.url);
    assert.equal(imagen.status, 200);
    assert.equal(imagen.headers['x-content-type-options'], 'nosniff');
  });

  it('fuerza la descarga de HTML que ya estuviera en uploads', async () => {
    const nombre = `${randomUUID()}.html`;
    fs.mkdirSync(config.uploadsDir, { recursive: true });
    fs.writeFileSync(path.join(config.uploadsDir, nombre), '<p>Prueba local</p>', { flag: 'wx' });
    try {
      const res = await agente().get(`/uploads/${nombre}`);
      assert.equal(res.status, 200);
      assert.equal(res.headers['content-disposition'], 'attachment');
      assert.equal(res.headers['content-security-policy'], 'sandbox');
    } finally {
      fs.rmSync(path.join(config.uploadsDir, nombre));
    }
  });
});
