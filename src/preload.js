// Safe bridge between the UI and the main process. The UI never gets Node access.
const { contextBridge, ipcRenderer, webUtils } = require('electron');
const inv = (ch) => (arg) => ipcRenderer.invoke(ch, arg);

contextBridge.exposeInMainWorld('cho', {
  status: inv('sys:status'),
  getSettings: inv('settings:get'),
  setSettings: inv('settings:set'),
  catalog: inv('catalog:get'),
  classify: (cmd, dir) => ipcRenderer.invoke('cmd:classify', { cmd, dir }),

  listChallenges: inv('challenge:list'),
  createChallenge: inv('challenge:create'),
  loadChallenge: inv('challenge:load'),
  saveChallenge: (dir, data) => ipcRenderer.invoke('challenge:save', { dir, data }),
  openFolder: inv('challenge:open-folder'),

  pickFiles: inv('files:pick'),
  pathForFile: (file) => webUtils.getPathForFile(file),
  addFiles: (dir, paths, flagPrefix) => ipcRenderer.invoke('files:add', { dir, paths, flagPrefix }),
  analyzeFile: (dir, rel, flagPrefix) => ipcRenderer.invoke('files:analyze', { dir, rel, flagPrefix }),
  tree: inv('files:tree'),
  readFile: (dir, rel, mode, offset) => ipcRenderer.invoke('files:read', { dir, rel, mode, offset }),
  readText: (dir, rel) => ipcRenderer.invoke('files:read-text', { dir, rel }),
  writeFile: (dir, rel, content) => ipcRenderer.invoke('files:write', { dir, rel, content }),
  analyzeText: (text, flagPrefix) => ipcRenderer.invoke('text:analyze', { text, flagPrefix }),

  fetchUrl: (dir, url) => ipcRenderer.invoke('net:fetch', { dir, url }),
  captureScreen: inv('screen:capture'),
  run: (opts) => ipcRenderer.invoke('proc:run', opts),
  kill: (id) => ipcRenderer.send('proc:kill', id),
  onData: (cb) => ipcRenderer.on('proc:data', (_e, d) => cb(d)),

  chat: inv('cho:chat'),
  stopChat: (id) => ipcRenderer.send('cho:stop', id),
  onToken: (cb) => ipcRenderer.on('cho:token', (_e, d) => cb(d)),
  pullModel: (id, model) => ipcRenderer.invoke('ollama:pull', { id, model }),
  openSetup: inv('setup:open'),
});
