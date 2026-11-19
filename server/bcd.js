'use strict';
/**
 * Разбор `bcdedit /enum firmware` (нужны права администратора): порядок загрузки UEFI.
 * Блоки разделены пустой строкой: заголовок, строка из «-», затем «ключ значение».
 * Ключ идентификатора переведён на язык Windows («identifier», «идентификатор»), поэтому
 * идентификатором считаем первое свойство блока. Остальные ключи (displayorder, description) - английские.
 */
function parseBlocks(text) {
  const blocks = [];
  for (const chunk of String(text || '').replace(/\r/g, '').split(/\n\s*\n/)) {
    const lines = chunk.split('\n').filter((l) => l.trim() !== '');
    const dash = lines.findIndex((l) => /^-{3,}\s*$/.test(l));
    if (dash < 0) continue;
    const props = [];
    for (const l of lines.slice(dash + 1)) {
      const m = /^(\S+)\s+(.*)$/.exec(l);
      if (m && !/^\s/.test(l)) props.push({ key: m[1].toLowerCase(), values: [m[2].trim()] });
      else if (props.length) props[props.length - 1].values.push(l.trim());
    }
    if (!props.length) continue;
    const get = (k) => (props.find((p) => p.key === k) || {}).values;
    blocks.push({ title: lines[0].trim(), id: props[0].values[0], props, get });
  }
  return blocks;
}

/** → [{ id, description }] в порядке загрузки. */
function parseBcdFirmware(text) {
  const blocks = parseBlocks(text);
  const mgr = blocks.find((b) => b.id === '{fwbootmgr}');
  if (!mgr) return [];
  const order = mgr.get('displayorder') || [];
  const byId = new Map(blocks.map((b) => [b.id, b]));
  return order.map((id) => {
    const b = byId.get(id);
    const d = b && (b.get('description') || b.get('описание'));
    return { id, description: d ? d[0] : id === '{bootmgr}' ? 'Windows Boot Manager' : id };
  });
}

module.exports = { parseBcdFirmware, parseBlocks };
