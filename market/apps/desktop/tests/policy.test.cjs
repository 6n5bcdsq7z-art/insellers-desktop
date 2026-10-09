const test = require('node:test');
const assert = require('node:assert/strict');
const { isInternal, isExternal } = require('../policy.cjs');
test('only the exact TLS application origin stays in the privileged window', () => {
  assert.equal(isInternal('https://bot.insellers.su/?app=desktop'), true);
  for (const url of ['http://bot.insellers.su', 'https://bot.insellers.su.evil.test', 'https://bot.insellers.su:444', 'file:///etc/passwd', 'javascript:alert(1)']) assert.equal(isInternal(url), false, url);
});
test('external navigation rejects code, local files and URL credentials', () => {
  for (const url of ['https://t.me/insellers_bot?startapp=native_x', 'tg://resolve?domain=insellers_bot', 'mailto:help@insellers.su']) assert.equal(isExternal(url), true, url);
  for (const url of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'https://user:pass@example.com']) assert.equal(isExternal(url), false, url);
});
