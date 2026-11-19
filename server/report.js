'use strict';
/**
 * Отчёт одним HTML-файлом: без скриптов и внешних ресурсов, открывается в любом браузере и печатается.
 */
const { render, tx, t } = require('./i18n');
const { SEVERITIES, CATEGORIES, summarize } = require('./rules');

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const SEV_LABEL = { critical: t('Критично'), high: t('Важно'), advice: t('Совет'), unknown: t('Не видно'), ok: t('В порядке') };
const SEV_COLOR = { critical: '#c62f4b', high: '#b86a12', advice: '#2d6fb3', unknown: '#6b7480', ok: '#23824f' };

function reportHtml({ report, scan, lang = 'ru', version = '' }) {
  const L = (m) => esc(render(lang, m));
  const findings = [...((report && report.findings) || []), ...((scan && scan.findings) || [])];
  const sum = summarize(findings);
  const meta = (report && report.facts && report.facts.meta) || {};
  const when = report ? new Date(report.at).toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU') : '-';
  const rows = SEVERITIES.map((sev) => {
    const list = findings.filter((f) => f.sev === sev);
    if (!list.length) return '';
    return `<h2 style="color:${SEV_COLOR[sev]}">${L(SEV_LABEL[sev])} · ${list.length}</h2>` + list.map((f) => `
<section class="f">
  <div class="cat">${L(CATEGORIES[f.cat] || f.cat)}</div>
  <h3>${L(f.title)}</h3>
  <p>${L(f.text)}</p>
  ${f.evidence && f.evidence.length ? `<ul>${f.evidence.map((e) => `<li>${L(e)}</li>`).join('')}</ul>` : ''}
</section>`).join('');
  }).join('');
  const title = render(lang, t('Адамант - отчёт о защите компьютера'));
  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} ${esc(meta.computer || '')}</title>
<style>
body{font:14px/1.5 "Segoe UI",system-ui,sans-serif;color:#1d2126;max-width:860px;margin:32px auto;padding:0 20px}
h1{font:600 24px "Bahnschrift","Segoe UI",sans-serif;margin:0 0 4px}
h2{font:600 17px "Bahnschrift","Segoe UI",sans-serif;margin:28px 0 8px;border-bottom:1px solid #dde1e6;padding-bottom:4px}
h3{font-size:15px;margin:2px 0 4px}
.muted{color:#66707c}.f{padding:10px 0;border-bottom:1px solid #eef0f3;break-inside:avoid}
.cat{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#66707c}
.sum{display:flex;gap:18px;flex-wrap:wrap;margin:16px 0}.sum b{font:600 22px "Bahnschrift",sans-serif;display:block}
ul{margin:4px 0 0;padding-left:20px;color:#3d444d}p{margin:0}
</style></head><body>
<h1>${esc(title)}</h1>
<div class="muted">${L(tx('Компьютер {0} · {1} · проверка {2}', meta.computer || '-', meta.osCaption || '', when))}${report && report.full ? ' · ' + L(t('полная проверка')) : ''}</div>
<div class="sum">${SEVERITIES.map((s) => `<div style="color:${SEV_COLOR[s]}"><b>${sum[s]}</b>${L(SEV_LABEL[s])}</div>`).join('')}</div>
${rows || `<p>${L(t('Проверка ещё не проводилась.'))}</p>`}
<p class="muted" style="margin-top:28px">${L(tx('Адамант {0}. Отчёт составлен на этом компьютере, никуда не отправлялся.', version))}</p>
</body></html>`;
}

module.exports = { reportHtml, esc, SEV_LABEL };
