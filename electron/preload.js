const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberthreatDesktop', {
  isDesktop: true,
  appVersion: '1.0.0',
  platform: process.platform,
  sendNotification: (title, body, urgency) => {
    ipcRenderer.send('send-desktop-notification', { title, body, urgency });
  }
});
