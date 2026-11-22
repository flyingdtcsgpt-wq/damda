// 담다 데스크톱 (Windows · Mac · Linux). 웹앱과 같은 화면을 전용 창에 담아 서버 없이 실행한다.
// 데이터는 운영체제의 앱 데이터 폴더에 암호화된 채로 저장된다.
const { app, BrowserWindow, protocol, net, shell, session } = require('electron');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', 'app');
protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true } }]);

let win;
function createWindow() {
  win = new BrowserWindow({
    width: 1200, height: 820, minWidth: 360, minHeight: 480, title: '담다', autoHideMenuBar: true, backgroundColor: '#f6f1e7',
    icon: path.join(ROOT, 'icons', 'icon-512.png'),
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: false },
  });
  win.loadURL('app://damda/');
  // 링크는 앱 창이 아니라 기본 브라우저에서 연다. 앱 창은 다른 곳으로 이동하지 못한다.
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https?:\/\//i.test(url)) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('app://damda/')) e.preventDefault(); });
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    protocol.handle('app', req => {
      const p = decodeURIComponent(new URL(req.url).pathname);
      const f = path.normalize(path.join(ROOT, p === '/' ? 'index.html' : p));
      if (!f.startsWith(ROOT)) return new Response('', { status: 403 });
      return net.fetch(pathToFileURL(f).toString());
    });
    // 녹음(마이크)과 복사만 허용하고 나머지 권한 요청은 거절한다.
    session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(perm === 'media' || perm === 'clipboard-sanitized-write'));
    createWindow();
    app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow(); });
  });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
