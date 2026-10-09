'use strict';
const ORIGIN = 'https://bot.insellers.su';
function isInternal(value) {
  try { const url = new URL(value); return url.origin === ORIGIN && !url.username && !url.password; } catch { return false; }
}
function isExternal(value) {
  try {
    const url = new URL(value);
    return ['https:', 'http:', 'mailto:', 'tel:', 'tg:'].includes(url.protocol) && !url.username && !url.password;
  } catch { return false; }
}
module.exports = { ORIGIN, isInternal, isExternal };
