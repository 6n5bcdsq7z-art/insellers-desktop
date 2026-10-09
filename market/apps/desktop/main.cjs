'use strict';
const { app, BrowserWindow, shell, Menu } = require('electron');
const { ORIGIN, isInternal, isExternal } = require('./policy.cjs');
const path = require('node:path');
let window;
const entry = ORIGIN + '/?app=desktop';
function openExternal(url) { if (isExternal(url)) shell.openExternal(url).catch(() => {}); }
function createWindow() {
  window = new BrowserWindow({
    title: 'INSELLERS', width: 1120, height: 800, minWidth: 360, minHeight: 560,
    backgroundColor: '#ffffff', autoHideMenuBar: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true,
      webSecurity: true, allowRunningInsecureContent: false }
  });
  window.webContents.setWindowOpenHandler(({ url }) => { openExternal(url); return { action: 'deny' }; });
  window.webContents.on('will-navigate', (event, url) => {
    if (!isInternal(url)) { event.preventDefault(); openExternal(url); }
  });
  window.webContents.on('will-redirect', (event, url) => {
    if (!isInternal(url)) { event.preventDefault(); openExternal(url); }
  });
  window.webContents.session.setPermissionRequestHandler((contents, permission, callback, details) => {
    // File selection uses the OS picker. Remote pages receive no microphone/location privileges.
    callback(contents === window.webContents && isInternal(details.requestingUrl) && permission === 'clipboard-sanitized-write');
  });
  window.webContents.session.setPermissionCheckHandler(() => false);
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.webContents.on('did-fail-load', (_event, code, _description, _url, isMainFrame) => {
    if (isMainFrame && code !== -3) window.loadFile(path.join(__dirname, 'offline.html'));
  });
  window.loadURL(entry);
  const menu = [{ label: 'INSELLERS', submenu: [
    { label: 'Обновить страницу', accelerator: 'CmdOrCtrl+R', click: () => window.loadURL(entry) },
    { label: 'Загрузить новую версию приложения', click: () => openExternal('https://github.com/6n5bcdsq7z-art/insellers-desktop/releases/latest') },
    { type: 'separator' }, { role: 'quit', label: 'Выйти' }
  ] }, { role: 'editMenu' }];
  if (process.platform === 'darwin') menu.push({ role: 'windowMenu' });
  Menu.setApplicationMenu(Menu.buildFromTemplate(menu));
}
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (window) { if (window.isMinimized()) window.restore(); window.focus(); } });
  app.whenReady().then(createWindow);
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
