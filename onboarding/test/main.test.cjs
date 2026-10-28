const test = require("node:test"),
  assert = require("node:assert/strict"),
  vm = require("node:vm"),
  fs = require("node:fs"),
  path = require("node:path");
const { pathToFileURL } = require("node:url");
test("only the main setup frame can provision; codes stay out of child arguments and temporary files are removed", async () => {
  const calls = [],
    writes = [],
    removed = [];
  let handler, window, options;
  const dirname = path.resolve(__dirname, "..");
  const fakeFS = {
    mkdtemp: async () => "/tmp/keen-setup-test",
    chmod: async () => {},
    mkdir: async () => {},
    writeFile: async (...args) => writes.push(args),
    rm: async (...args) => removed.push(args),
  };
  class Window {
    constructor(o) {
      options = o;
      window = this;
      this.webContents = {
        mainFrame: {
          url: pathToFileURL(path.join(dirname, "ui/index.html")).href,
        },
        setWindowOpenHandler: () => {},
        on: () => {},
      };
    }
    on() {}
    loadFile() {}
    show() {}
    focus() {}
  }
  const electron = {
    app: {
      requestSingleInstanceLock: () => true,
      on: () => {},
      whenReady: () => Promise.resolve(),
      getPath: () => "/home/test",
      isPackaged: true,
    },
    BrowserWindow: Window,
    session: {
      defaultSession: {
        setPermissionRequestHandler: () => {},
        setPermissionCheckHandler: () => {},
      },
    },
    ipcMain: {
      handle: (_name, fn) => {
        handler = fn;
      },
    },
  };
  const requireMock = (name) => {
    if (name === "electron") return electron;
    if (name === "node:fs/promises") return fakeFS;
    if (name === "node:child_process")
      return {
        execFile: (file, args, _options, callback) => {
          calls.push([file, args]);
          setImmediate(() => callback(null, ""));
        },
      };
    if (name === "./validation.cjs") return require("../validation.cjs");
    return require(name);
  };
  vm.runInNewContext(fs.readFileSync(path.join(dirname, "main.cjs"), "utf8"), {
    require: requireMock,
    __dirname: dirname,
    process: { platform: "linux", env: {} },
    Buffer,
  });
  await new Promise((r) => setImmediate(r));
  const request = { url: "keen.example", code: "kc_6f8459a2-2768-41a4-94d5-a0cdcc2d7187.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
  const denied = await handler(
    {
      sender: window.webContents,
      senderFrame: { url: window.webContents.mainFrame.url },
    },
    request,
  );
  assert.equal(denied.ok, false);
  assert.equal(writes.length, 0);
  assert.equal(options.webPreferences.sandbox, true);
  assert.equal(options.webPreferences.contextIsolation, true);
  assert.equal(options.webPreferences.nodeIntegration, false);
  const success = await handler(
    { sender: window.webContents, senderFrame: window.webContents.mainFrame },
    request,
  );
  assert.equal(success.ok, true);
  const secret = writes.find(([file]) => file.endsWith("request.json"));
  assert.equal(JSON.parse(secret[1]).code, request.code);
  assert.equal(secret[2].mode, 0o600);
  assert.equal(secret[2].flag, "wx");
  assert.equal(JSON.stringify(calls).includes(request.code), false);
  assert.equal(calls[0][0], "/usr/bin/pkexec");
  assert.equal(calls[0][1][0], "/usr/libexec/keen-setup-helper");
  assert.equal(removed[0][0], "/tmp/keen-setup-test");
});
