'use strict';
/**
 * PNG без внешних библиотек: чтение (8 бит, RGB/RGBA/серый, без чересстрочности), уменьшение
 * с учётом прозрачности (усреднение по площади, premultiplied alpha) и запись RGBA.
 * Нужен, чтобы из картинок ChatGPT (art/*.png) собрать значок и картинки окна.
 */
const zlib = require('node:zlib');

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

let CRC = null;
function crc32(buf) {
  if (typeof zlib.crc32 === 'function') return zlib.crc32(buf) >>> 0;
  if (!CRC) {
    CRC = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** → { width, height, data: RGBA Buffer } */
function decode(buf) {
  if (!buf.subarray(0, 8).equals(SIG)) throw new Error('это не PNG');
  let p = 8;
  let width, height, depth, type, interlace, palette, trns;
  const idat = [];
  while (p < buf.length) {
    const len = buf.readUInt32BE(p);
    const kind = buf.toString('ascii', p + 4, p + 8);
    const data = buf.subarray(p + 8, p + 8 + len);
    if (kind === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      depth = data[8];
      type = data[9];
      interlace = data[12];
    } else if (kind === 'PLTE') palette = data;
    else if (kind === 'tRNS') trns = data;
    else if (kind === 'IDAT') idat.push(data);
    else if (kind === 'IEND') break;
    p += 12 + len;
  }
  if (depth !== 8 || interlace) throw new Error(`PNG: поддерживается только 8 бит без чересстрочности (depth ${depth}, interlace ${interlace})`);
  const ch = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[type];
  if (!ch) throw new Error('PNG: неизвестный тип цвета ' + type);
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * ch;
  const out = Buffer.alloc(width * height * 4);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const f = raw[y * (stride + 1)];
    const line = Buffer.from(raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)));
    for (let x = 0; x < stride; x++) {
      const a = x >= ch ? line[x - ch] : 0;
      const b = prev[x];
      const c = x >= ch ? prev[x - ch] : 0;
      let v = 0;
      if (f === 1) v = a;
      else if (f === 2) v = b;
      else if (f === 3) v = (a + b) >> 1;
      else if (f === 4) {
        const pp = a + b - c;
        const pa = Math.abs(pp - a), pb = Math.abs(pp - b), pc = Math.abs(pp - c);
        v = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      line[x] = (line[x] + v) & 255;
    }
    for (let x = 0; x < width; x++) {
      const o = (y * width + x) * 4;
      const s = x * ch;
      if (type === 6) line.copy(out, o, s, s + 4);
      else if (type === 2) { out[o] = line[s]; out[o + 1] = line[s + 1]; out[o + 2] = line[s + 2]; out[o + 3] = 255; }
      else if (type === 0) { out[o] = out[o + 1] = out[o + 2] = line[s]; out[o + 3] = 255; }
      else if (type === 4) { out[o] = out[o + 1] = out[o + 2] = line[s]; out[o + 3] = line[s + 1]; }
      else if (type === 3) {
        const i = line[s];
        out[o] = palette[i * 3]; out[o + 1] = palette[i * 3 + 1]; out[o + 2] = palette[i * 3 + 2];
        out[o + 3] = trns && i < trns.length ? trns[i] : 255;
      }
    }
    prev = line;
  }
  return { width, height, data: out };
}

function encode({ width, height, data }) {
  const chunk = (type, body) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(body.length);
    const td = Buffer.concat([Buffer.from(type, 'ascii'), body]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const stride = width * 4;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y++) {
    // Фильтр «Sub» для каждой строки - заметно лучше сжимает фотографии.
    const o = y * (stride + 1);
    raw[o] = 1;
    for (let x = 0; x < stride; x++) raw[o + 1 + x] = (data[y * stride + x] - (x >= 4 ? data[y * stride + x - 4] : 0)) & 255;
  }
  return Buffer.concat([SIG, chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

/** Уменьшение усреднением по площади с учётом прозрачности. */
function resize(img, w, h) {
  const { width: W, height: H, data } = img;
  const out = Buffer.alloc(w * h * 4);
  const sx = W / w;
  const sy = H / h;
  for (let y = 0; y < h; y++) {
    const y0 = y * sy, y1 = y0 + sy;
    for (let x = 0; x < w; x++) {
      const x0 = x * sx, x1 = x0 + sx;
      let r = 0, g = 0, b = 0, a = 0, area = 0;
      for (let yy = Math.floor(y0); yy < Math.ceil(y1); yy++) {
        const wy = Math.min(y1, yy + 1) - Math.max(y0, yy);
        for (let xx = Math.floor(x0); xx < Math.ceil(x1); xx++) {
          const wgt = wy * (Math.min(x1, xx + 1) - Math.max(x0, xx));
          const o = (yy * W + xx) * 4;
          const al = data[o + 3] / 255;
          r += data[o] * al * wgt; g += data[o + 1] * al * wgt; b += data[o + 2] * al * wgt;
          a += al * wgt;
          area += wgt;
        }
      }
      const o = (y * w + x) * 4;
      if (a > 0) {
        out[o] = Math.round(r / a); out[o + 1] = Math.round(g / a); out[o + 2] = Math.round(b / a);
      }
      out[o + 3] = Math.round((a / area) * 255);
    }
  }
  return { width: w, height: h, data: out };
}

/** Обрезка по непрозрачной части и вписывание в квадрат с полями (доля margin с каждой стороны). */
function fitSquare(img, size, margin = 0.04) {
  const { width: W, height: H, data } = img;
  let minX = W, minY = H, maxX = -1, maxY = -1;
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    if (data[(y * W + x) * 4 + 3] > 8) {
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;
    }
  }
  if (maxX < 0) throw new Error('картинка полностью прозрачная');
  const side = Math.max(maxX - minX + 1, maxY - minY + 1);
  const pad = Math.round(side * margin / (1 - 2 * margin));
  const S = side + 2 * pad;
  const sq = { width: S, height: S, data: Buffer.alloc(S * S * 4) };
  const ox = pad + Math.floor((side - (maxX - minX + 1)) / 2);
  const oy = pad + Math.floor((side - (maxY - minY + 1)) / 2);
  for (let y = minY; y <= maxY; y++) data.copy(sq.data, ((oy + y - minY) * S + ox) * 4, (y * W + minX) * 4, (y * W + maxX + 1) * 4);
  return resize(sq, size, size);
}

module.exports = { decode, encode, resize, fitSquare, crc32 };
