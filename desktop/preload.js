// 화면 쪽에 꼭 필요한 기능 하나만 내준다.
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('damdaNative', { fetchImage: url => ipcRenderer.invoke('fetch-image', url) });
