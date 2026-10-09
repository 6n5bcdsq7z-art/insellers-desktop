const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createUpdates } = require('../updates.cjs');
const flush = () => new Promise(resolve => setImmediate(resolve));
function setup(responses = []) {
  const updater = new EventEmitter(); let downloads = 0, installs = 0, checks = 0;
  updater.downloadUpdate = async () => { downloads++; updater.emit('download-progress',{percent:50}); updater.emit('update-downloaded'); };
  updater.quitAndInstall = () => installs++;
  updater.checkForUpdates = async () => { checks++; updater.emit('update-available',{version:'1.0.9'}); };
  const messages = [], progress = [];
  const result = createUpdates({updater, app:{isPackaged:true},getWindow:()=>({isDestroyed:()=>false,setProgressBar:p=>progress.push(p)}),
    dialog:{showMessageBox:async (_window,opts)=>{messages.push(opts);return {response:responses.shift() ?? 1};}}});
  return {result,updater,messages,progress,counts:()=>({downloads,installs,checks})};
}
test('background discovery never downloads or installs without consent',async()=>{
  const s=setup([1]);await s.result.check();await flush();assert.deepEqual(s.counts(),{downloads:0,installs:0,checks:1});
  await s.result.check();await flush();assert.equal(s.messages.length,1);
});
test('download and restart require separate consent, with progress',async()=>{
  const s=setup([0,0]);await s.result.check(true);await flush();await flush();
  assert.deepEqual(s.counts(),{downloads:1,installs:1,checks:1});assert(s.progress.includes(0.5));
});
test('deferred installation remains available without redownloading',async()=>{
  const s=setup([0,1,0]);await s.result.check(true);await flush();await flush();assert.equal(s.counts().installs,0);
  await s.result.check(true);assert.equal(s.counts().installs,1);assert.equal(s.counts().downloads,1);
});
test('manual check failure gives feedback and never starts installer',async()=>{
  const s=setup();s.updater.checkForUpdates=async()=>{s.updater.emit('error',new Error('offline'));throw Error('offline');};
  await s.result.check(true);await flush();assert.equal(s.messages[0].type,'error');assert.equal(s.counts().installs,0);
});
