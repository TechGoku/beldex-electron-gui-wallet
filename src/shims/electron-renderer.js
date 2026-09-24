const electronAPI = window.electronAPI;

export const clipboard = {
  writeText: text => electronAPI.clipboard.writeText(text),
  writeImage: image => {
    const dataUrl = image && image.dataUrl ? image.dataUrl : image;
    electronAPI.clipboard.writeImageFromDataUrl(dataUrl);
  }
};

export const nativeImage = {
  createFromDataURL: dataUrl => ({
    dataUrl
  })
};

export const appIpc = {
  on: (channel, listener) => electronAPI.ipc.on(channel, listener),
  send: (channel, ...args) => electronAPI.ipc.send(channel, ...args)
};

export const shell = {
  openExternal: url => electronAPI.shell.openExternal(url)
};

// File.path was removed in Electron 32
export const getPathForFile = file =>
  file ? electronAPI.files.getPathForFile(file) : "";

// Native folder picker (empty string when cancelled)
export const selectDirectory = defaultPath =>
  electronAPI.dialog.selectDirectory(defaultPath);
