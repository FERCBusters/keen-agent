const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("keenSetup", {
  connect: (request) => ipcRenderer.invoke("keen:connect", request),
});
