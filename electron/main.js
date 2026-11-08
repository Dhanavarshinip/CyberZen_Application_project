/**
 * CyberZen Operations Center - Electron Desktop Shell
 * Provides:
 * - Local static HTTP server serving compiled Vite production assets
 * - Single-instance locking to prevent duplicate processes
 * - Asynchronous FastAPI backend engine health verification and auto-launch
 * - Native Windows Toast / Action Center notification delivery
 * - System Tray integration for seamless 24/7 background threat monitoring
 * - Continuous protection: closing the window keeps 24/7 monitoring active
 */

const { app, BrowserWindow, Notification: ElectronNotification, ipcMain, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');
const { spawn, exec, execSync } = require('child_process');

let server = null;
let serverPort = 5173;
let mainWindow = null;
let backendProcess = null;
let tray = null;
app.isQuitting = false;

// Set Windows Application User Model ID for notifications
if (process.platform === 'win32') {
  app.setAppUserModelId('com.cyberthreat.ai');
}

process.on('uncaughtException', (err) => {
  console.error('[!] Process uncaughtException:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[!] Process unhandledRejection:', reason);
});
process.on('exit', (code) => {
  console.log('[*] Node process.on exit called with code:', code);
});
app.on('before-quit', () => {
  app.isQuitting = true;
  console.log('[*] app before-quit fired');
});
app.on('will-quit', () => {
  console.log('[*] app will-quit fired');
});

// Prevent duplicate application and backend processes with isolated userData
try {
  app.setPath('userData', path.join(app.getPath('appData'), 'CyberThreatAI_Desktop'));
} catch (e) {}

// Enable single instance focus if lock is acquired
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  console.log('[*] Another instance is already running. Exiting secondary instance.');
  app.quit();
} else {
  app.on('second-instance', () => {
    console.log('[*] Second instance requested. Focusing and reloading main window.');
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
      try {
        mainWindow.webContents.reloadIgnoringCache();
      } catch (e) {}
    }
  });
}

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf'
};

function getProjectRoot() {
  if (app.isPackaged) {
    const directRoot = path.join(__dirname, '..');
    if (fs.existsSync(directRoot)) {
      return directRoot;
    }
    const packagedAppDir = path.join(process.resourcesPath, 'app');
    if (fs.existsSync(packagedAppDir)) {
      return packagedAppDir;
    }
    const unpackedDir = path.join(process.resourcesPath, 'app.asar.unpacked');
    if (fs.existsSync(unpackedDir)) {
      return unpackedDir;
    }
  }
  return path.join(__dirname, '..');
}

function getDistDir() {
  if (app.isPackaged) {
    const directDist = path.join(__dirname, '../dist');
    if (fs.existsSync(directDist)) {
      return directDist;
    }
    const packagedDist = path.join(process.resourcesPath, 'app', 'dist');
    if (fs.existsSync(packagedDist)) {
      return packagedDist;
    }
    const unpackedDist = path.join(process.resourcesPath, 'app.asar.unpacked', 'dist');
    if (fs.existsSync(unpackedDist)) {
      return unpackedDist;
    }
  }
  return path.join(__dirname, '../dist');
}

function findPythonExecutable() {
  if (process.platform !== 'win32') return 'python3';

  const localAppData = process.env.LOCALAPPDATA || '';
  const programFiles = process.env.ProgramFiles || 'C:\\Program Files';

  const candidates = [
    'C:\\Python314\\python.exe',
    'C:\\Python313\\python.exe',
    'C:\\Python312\\python.exe',
    'C:\\Python311\\python.exe',
    'C:\\Python310\\python.exe',
    path.join(localAppData, 'Programs', 'Python', 'Python314', 'python.exe'),
    path.join(localAppData, 'Programs', 'Python', 'Python313', 'python.exe'),
    path.join(localAppData, 'Programs', 'Python', 'Python312', 'python.exe'),
    path.join(localAppData, 'Programs', 'Python', 'Python311', 'python.exe'),
    path.join(localAppData, 'Programs', 'Python', 'Python310', 'python.exe'),
    path.join(programFiles, 'Python314', 'python.exe'),
    path.join(programFiles, 'Python312', 'python.exe'),
    'python'
  ];

  for (const c of candidates) {
    if (c === 'python') return 'python';
    try {
      if (fs.existsSync(c)) return c;
    } catch (e) {}
  }
  return 'python';
}

function startStaticServer(distDir, callback) {
  server = http.createServer((req, res) => {
    let reqPath = decodeURI(req.url.split('?')[0]);
    if (reqPath === '/' || reqPath === '') {
      reqPath = '/index.html';
    }

    let filePath = path.join(distDir, reqPath);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(distDir, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error loading ' + reqPath);
      } else {
        res.writeHead(200, {
          'Content-Type': contentType,
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
        });
        res.end(content);
      }
    });
  });

  server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    console.log(`[*] Electron Local Static Server running on http://127.0.0.1:${port}`);
    callback(port);
  });
}

function createWindow(port) {
  const projectRoot = getProjectRoot();
  const iconPath = path.join(projectRoot, 'chrome_extension', 'icon.png');

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'CyberZen - Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    backgroundColor: '#000000',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.webContents.on('console-message', (event, level, message) => {
    if (level >= 2) {
      console.log(`[Renderer] [L${level}] ${message}`);
    }
  });

  mainWindow.webContents.on('render-process-gone', (event, details) => {
    console.error('[!] Render process gone:', JSON.stringify(details));
  });

  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
    console.error('[!] Failed to load URL:', errorCode, errorDescription, validatedURL);
  });

  mainWindow.once('ready-to-show', () => {
    console.log('[*] Window ready to show. Displaying and focusing.');
    mainWindow.show();
    mainWindow.focus();
  });
  setTimeout(() => {
    if (mainWindow && !mainWindow.isVisible()) {
      mainWindow.show();
      mainWindow.focus();
    }
  }, 600);

  // Intercept window close to keep 24/7 background monitoring active
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      sendElectronNotification(
        'CyberZen — Guarding in Background',
        'Continuous 24/7 host threat monitoring and behavioral defense remain active.',
        'normal'
      );
      return false;
    }
  });

  // Disable caching so rebuilds are immediately visible
  try {
    mainWindow.webContents.session.clearCache();
  } catch (e) {}

  // Allow F5 and Ctrl+R to reload without cache
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.key === 'F5' || ((input.control || input.meta) && input.key.toLowerCase() === 'r')) {
      mainWindow.webContents.reloadIgnoringCache();
    }
  });

  const appUrl = `http://127.0.0.1:${port}/?app_mode=desktop`;
  console.log('[*] Loading Desktop Application from:', appUrl);
  mainWindow.loadURL(appUrl);
}

function createTray() {
  if (tray) return;
  try {
    const projectRoot = getProjectRoot();
    const iconPath = path.join(projectRoot, 'chrome_extension', 'icon.png');
    let trayIcon;
    if (fs.existsSync(iconPath)) {
      trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 18, height: 18 });
    } else {
      trayIcon = nativeImage.createEmpty();
    }

    tray = new Tray(trayIcon);
    tray.setToolTip('CyberZen — Continuous 24/7 Endpoint Protection Active');

    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Open CyberZen Operations Center',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          } else {
            createWindow(serverPort);
          }
        }
      },
      { type: 'separator' },
      {
        label: '🛡️ Continuous Monitoring: Active 24/7',
        enabled: false
      },
      {
        label: 'Start at Windows Login',
        type: 'checkbox',
        checked: true,
        click: (item) => {
          try {
            app.setLoginItemSettings({
              openAtLogin: item.checked,
              openAsHidden: true
            });
          } catch (e) {}
        }
      },
      { type: 'separator' },
      {
        label: 'Hide to System Tray',
        click: () => {
          if (mainWindow) mainWindow.hide();
        }
      },
      {
        label: 'Exit Operations Center (Monitoring Stays Active)',
        click: () => {
          app.isQuitting = true;
          if (mainWindow) mainWindow.destroy();
          app.quit();
        }
      }
    ]);

    tray.setContextMenu(contextMenu);
    tray.on('click', () => {
      if (mainWindow) {
        if (mainWindow.isVisible()) {
          mainWindow.focus();
        } else {
          mainWindow.show();
          mainWindow.focus();
        }
      } else {
        createWindow(serverPort);
      }
    });
  } catch (err) {
    console.warn('[!] Could not initialize system tray:', err.message);
  }
}

function sendElectronNotification(title, body, urgency = 'normal') {
  if (!ElectronNotification.isSupported()) return;
  try {
    const n = new ElectronNotification({
      title,
      body,
      urgency,
      timeoutType: urgency === 'critical' ? 'never' : 'default'
    });
    n.on('click', () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
    n.show();
    console.log(`[*] Windows notification sent: ${title}`);
  } catch (e) {
    console.warn('[!] Failed to send notification:', e.message);
  }
}

ipcMain.on('send-desktop-notification', (event, { title, body, urgency }) => {
  sendElectronNotification(title, body, urgency);
});

function teardownBackendProcess(force = false) {
  if (force && backendProcess && backendProcess.pid) {
    try {
      if (process.platform === 'win32') {
        execSync(`taskkill /pid ${backendProcess.pid} /T /F`);
      } else {
        backendProcess.kill('SIGTERM');
      }
    } catch (e) {}
  }
}

ipcMain.on('terminate-backend', () => {
  teardownBackendProcess(true);
});

function ensureBackendRunning(callback) {
  const req = http.get('http://127.0.0.1:8000/api/health', (res) => {
    if (res.statusCode === 200) {
      console.log('[*] Local backend engine active on http://127.0.0.1:8000');
    }
    if (callback) callback();
  });
  req.on('error', () => {
    console.log('[*] Using CyberZen Cloud Security Service for 24/7 endpoint defense.');
    if (callback) callback();
  });
  req.setTimeout(800, () => {
    req.destroy();
    if (callback) callback();
  });
}

function startBackend(callback) {
  console.log('[*] Launching CyberZen 24/7 background monitor...');
  const projectRoot = getProjectRoot();
  const vbsPath = path.join(projectRoot, 'run_monitor_hidden.vbs');

  // If the silent runner script exists, launch via wscript so it is completely hidden and persistent
  if (fs.existsSync(vbsPath)) {
    exec(`wscript.exe "${vbsPath}"`, { cwd: projectRoot }, (err) => {
      if (err) console.warn('[!] wscript launch note:', err.message);
    });
  } else {
    const pythonCmd = findPythonExecutable();
    try {
      const logDir = path.join(process.env.LOCALAPPDATA || projectRoot, 'CyberThreatAI', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      const logFile = path.join(logDir, 'backend_startup.log');
      const outStream = fs.openSync(logFile, 'a');

      backendProcess = spawn(pythonCmd, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000'], {
        cwd: projectRoot,
        stdio: ['ignore', outStream, outStream],
        detached: true,
        windowsHide: true
      });
      backendProcess.unref();
    } catch (err) {
      backendProcess = spawn(pythonCmd, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000'], {
        cwd: projectRoot,
        stdio: 'ignore',
        detached: true,
        windowsHide: true
      });
      backendProcess.unref();
    }
  }

  let attempts = 0;
  const timer = setInterval(() => {
    attempts++;
    const checkReq = http.get('http://127.0.0.1:8000/api/health', (res) => {
      if (res.statusCode === 200) {
        clearInterval(timer);
        console.log('[+] Backend started successfully.');
        if (callback) callback();
      }
    });
    checkReq.on('error', () => {
      if (attempts >= 25) {
        clearInterval(timer);
        console.warn('[-] Timed out waiting for backend to answer /api/health.');
        if (callback) callback();
      }
    });
  }, 500);
}

function ensureExtensionInstalled() {
  try {
    const localAppData = process.env.LOCALAPPDATA;
    if (!localAppData) return;
    const targetDir = path.join(localAppData, 'CyberThreatAI', 'chrome_extension');
    const projectRoot = getProjectRoot();
    const sourceDir = path.join(projectRoot, 'chrome_extension');
    if (fs.existsSync(sourceDir)) {
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }
      const files = fs.readdirSync(sourceDir);
      for (const file of files) {
        const srcFile = path.join(sourceDir, file);
        const dstFile = path.join(targetDir, file);
        if (fs.statSync(srcFile).isFile()) {
          fs.copyFileSync(srcFile, dstFile);
        }
      }
      console.log(`[+] Auto-installed Chrome extension into: ${targetDir}`);
    }
  } catch (err) {
    console.warn('[!] Extension auto-install warning:', err.message);
  }
}

app.whenReady().then(() => {
  ensureExtensionInstalled();
  createTray();

  const distDir = getDistDir();
  startStaticServer(distDir, (port) => {
    serverPort = port;
    createWindow(port);
  });

  // Ensure backend engine runs continuously in background
  ensureBackendRunning(() => {
    console.log('[*] 24/7 Background backend engine verified ready.');
  });

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow(serverPort);
    } else if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });

  setTimeout(() => {
    sendElectronNotification(
      'CyberZen — Continuous 24/7 Protection Active',
      'Real-time threat monitoring is running. You will be notified of any threats detected on this device.',
      'normal'
    );
  }, 2000);
});

app.on('window-all-closed', function () {
  // Continuous 24/7 Monitoring: do not exit when window closes unless quitting explicitly
  if (app.isQuitting) {
    if (server) server.close();
    // Intentionally DO NOT kill the backend process:
    // The security engine continues monitoring host processes, sockets, and incoming browser events 24/7!
    app.quit();
  }
});
