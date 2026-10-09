'use strict';
// Native dialogs only: the remote webpage receives no privileged update IPC.
function createUpdates({ updater, dialog, app, getWindow, timers = globalThis }) {
  let checking = false, downloading = false, manual = false, ready = false, offered = '';
  updater.autoDownload = false;
  updater.autoInstallOnAppQuit = false;
  const box = options => {
    const window = getWindow(), message = { title: 'Обновление INSELLERS', ...options };
    return window && !window.isDestroyed() ? dialog.showMessageBox(window, message) : dialog.showMessageBox(message);
  };
  function progress(value) { const w = getWindow(); if (w && !w.isDestroyed()) w.setProgressBar(value); }
  async function download() {
    if (downloading || ready) return;
    downloading = true; progress(0);
    try { await updater.downloadUpdate(); }
    catch { /* updater emits the diagnostic error event */ }
    finally { downloading = false; progress(-1); }
  }
  updater.on('update-available', async info => {
    if (!manual && offered === info.version) return;
    offered = info.version;
    const result = await box({ type: 'info', message: 'Доступна версия ' + info.version,
      detail: 'Скачать обновление приложения? Ваш аккаунт и данные сохранятся.', buttons: ['Скачать', 'Позже'], defaultId: 0, cancelId: 1 });
    if (result.response === 0) await download();
  });
  updater.on('update-not-available', () => {
    if (manual) void box({ type: 'info', message: 'Установлена последняя версия.', buttons: ['Хорошо'] });
  });
  updater.on('download-progress', info => progress(Math.max(0, Math.min(1, info.percent / 100))));
  updater.on('update-downloaded', async () => {
    ready = true; progress(-1);
    const result = await box({ type: 'info', message: 'Обновление скачано', detail: 'Перезапустить INSELLERS и установить обновление?',
      buttons: ['Перезапустить и обновить', 'Позже'], defaultId: 0, cancelId: 1 });
    if (result.response === 0) updater.quitAndInstall(false, true);
  });
  updater.on('error', () => {
    progress(-1);
    if (manual || downloading) void box({ type: 'error', message: 'Не удалось обновить приложение.',
      detail: 'Проверьте интернет и попробуйте ещё раз. На Mac для установки через обновлятор требуется подписанная версия приложения.', buttons: ['Хорошо'] });
  });
  async function check(isManual = false) {
    if (ready) {
      const result = await box({ type: 'info', message: 'Обновление готово к установке', buttons: ['Перезапустить и обновить', 'Позже'], cancelId: 1 });
      if (result.response === 0) updater.quitAndInstall(false, true);
      return;
    }
    if (checking || downloading || !app.isPackaged) return;
    checking = true; manual = isManual;
    try { await updater.checkForUpdates(); } catch { /* error event handles feedback */ }
    finally { checking = false; manual = false; }
  }
  function start() {
    if (!app.isPackaged) return;
    const initial = timers.setTimeout(() => void check(), 15000);
    const repeat = timers.setInterval(() => void check(), 6 * 60 * 60 * 1000);
    initial.unref?.(); repeat.unref?.();
  }
  return { check, start };
}
module.exports = { createUpdates };
