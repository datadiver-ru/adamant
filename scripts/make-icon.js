'use strict';
/**
 * Значок и картинки «Адаманта» из картинок ChatGPT в папке art/ (без внешних программ):
 *   art/icon.png → windows/adamant.ico - 16, 24, 32, 48, 64, 128, 256 пикселей (PNG внутри ICO);
 *                  public/favicon.png  - 256 пикселей (значок окна и панели задач);
 *                  public/img/diamond.png - 512 пикселей (камень в сводке и на экране ожидания).
 * Картинка обрезается по непрозрачной части и вписывается в квадрат с небольшими полями.
 * Запуск: npm run icon
 */
const fs = require('node:fs');
const path = require('node:path');
const { decode, encode, fitSquare } = require('./png');

const ROOT = path.resolve(__dirname, '..');
const SIZES = [16, 24, 32, 48, 64, 128, 256];

function ico(images) {
  const head = Buffer.alloc(6 + 16 * images.length);
  head.writeUInt16LE(0, 0);
  head.writeUInt16LE(1, 2);
  head.writeUInt16LE(images.length, 4);
  let offset = head.length;
  images.forEach(({ size, data }, i) => {
    const e = 6 + 16 * i;
    head[e] = size >= 256 ? 0 : size;
    head[e + 1] = size >= 256 ? 0 : size;
    head.writeUInt16LE(1, e + 4);
    head.writeUInt16LE(32, e + 6);
    head.writeUInt32LE(data.length, e + 8);
    head.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });
  return Buffer.concat([head, ...images.map((x) => x.data)]);
}

function build() {
  const src = decode(fs.readFileSync(path.join(ROOT, 'art', 'icon.png')));
  // В маленьких размерах поля меньше: камень должен занимать весь значок.
  const images = SIZES.map((size) => ({ size, data: encode(fitSquare(src, size, size <= 32 ? 0.01 : 0.03)) }));
  fs.writeFileSync(path.join(ROOT, 'windows', 'adamant.ico'), ico(images));
  fs.writeFileSync(path.join(ROOT, 'public', 'favicon.png'), images[images.length - 1].data);
  fs.mkdirSync(path.join(ROOT, 'public', 'img'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'public', 'img', 'diamond.png'), encode(fitSquare(src, 512, 0.03)));
  return images;
}

if (require.main === module) {
  build();
  console.log('Готово: windows/adamant.ico, public/favicon.png, public/img/diamond.png');
}

module.exports = { ico, build, SIZES };
