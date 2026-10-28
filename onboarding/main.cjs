"use strict";
const { app, BrowserWindow, ipcMain, session } = require("electron");
const fs = require("node:fs/promises"),
  path = require("node:path"),
  os = require("node:os");
const { execFile } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const { validate, messages, exitCode } = require("./validation.cjs");
let win,
  busy = false;
const page = pathToFileURL(path.join(__dirname, "ui/index.html")).href;
function execute(file, args, options = {}) {
  return new Promise((resolve) =>
    execFile(
      file,
      args,
      { timeout: 300000, maxBuffer: 8192, windowsHide: true, ...options },
      (error, stdout) =>
        resolve({
          code: error ? (Number.isInteger(error.code) ? error.code : 1) : 0,
          stdout: stdout || "",
        }),
    ),
  );
}
const psQuote = (s) => "'" + s.replaceAll("'", "''") + "'";
const shQuote = (s) => "'" + s.replaceAll("'", "'\\''") + "'";
function powershell(script) {
  const exe = path.join(
    process.env.SystemRoot || "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  return execute(exe, [
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    Buffer.from(script, "utf16le").toString("base64"),
  ]);
}
async function provision(request) {
  let dir;
  try {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "keen-setup-"));
    await fs.chmod(dir, 0o700);
    if (process.platform === "win32") {
      const result = await powershell(
        `$ErrorActionPreference='Stop'; $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetSecurityDescriptorSddlForm('O:'+ $sid +'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'); Set-Acl -LiteralPath ${psQuote(dir)} -AclObject $acl`,
      );
      if (result.code !== 0)
        throw new Error("Unable to create protected temporary storage.");
    }
    const file = path.join(dir, "request.json");
    await fs.writeFile(file, JSON.stringify(request), {
      mode: 0o600,
      flag: "wx",
    });
    let code;
    if (process.platform === "linux") {
      ({ code } = await execute("/usr/bin/pkexec", [
        "/usr/libexec/keen-setup-helper",
        "-request",
        file,
      ]));
    } else if (process.platform === "darwin") {
      const command =
        "/usr/local/libexec/keen-setup-helper -request " + shQuote(file);
      const script = `try\n do shell script ${JSON.stringify(command)} with administrator privileges\n return "0"\non error message number code\n return code as string\nend try`;
      const r = await execute("/usr/bin/osascript", ["-e", script]);
      code = r.code === 0 ? exitCode(r.stdout) : r.code;
    } else if (process.platform === "win32") {
      // Installed UI lives in Program Files/KEEN Posture/Setup, beside the helper.
      const helper = path.resolve(
        path.dirname(process.execPath),
        "..",
        "keen-setup-helper.exe",
      );
      const r = await powershell(
        `$ErrorActionPreference='Stop'; try { $p=Start-Process -FilePath ${psQuote(helper)} -ArgumentList @('-request',${psQuote('"' + file + '"')}) -Verb RunAs -Wait -PassThru; Write-Output $p.ExitCode } catch { Write-Output 1223 }`,
      );
      code = r.code === 0 ? exitCode(r.stdout) : r.code;
    } else throw new Error("This operating system is not supported.");
    if (code !== 0)
      throw new Error(
        messages[code] ||
          ([126, 127, 1223, -128].includes(code)
            ? "Setup was cancelled or administrator approval was unavailable."
            : "Setup could not finish. Check that the complete KEEN workstation package is installed."),
      );
    if (process.platform === "linux") {
      // Desktop settings must be collected in the signed-in user's session.
      const autostart = path.join(app.getPath("home"), ".config", "autostart");
      await fs.mkdir(autostart, { recursive: true, mode: 0o700 });
      await fs.writeFile(
        path.join(autostart, "keen-posture-session.desktop"),
        "[Desktop Entry]\nType=Application\nName=KEEN desktop posture\nExec=/usr/bin/systemctl --user start keen-posture-session.timer\nNoDisplay=true\n",
        { mode: 0o600 },
      );
      await execute("/usr/bin/systemctl", ["--user", "daemon-reload"]);
      const r = await execute("/usr/bin/systemctl", [
        "--user",
        "enable",
        "--now",
        "keen-posture-session.timer",
      ]);
      if (r.code !== 0)
        return {
          ok: true,
          warning:
            "Host posture is enabled. Desktop posture will start at your next graphical login; its session timer could not be started now.",
        };
    }
    return { ok: true };
  } finally {
    // No code is stored by Electron after this operation. Remove on success/failure/cancel.
    request.code = "";
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  }
}
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on("second-instance", () => {
    win?.show();
    win?.focus();
  });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_w, _p, callback) =>
      callback(false),
    );
    session.defaultSession.setPermissionCheckHandler(() => false);
    win = new BrowserWindow({
      width: 650,
      height: 680,
      minWidth: 520,
      minHeight: 600,
      title: "KEEN Setup",
      icon: path.join(__dirname, "icon.png"),
      autoHideMenuBar: true,
      webPreferences: {
        preload: path.join(__dirname, "preload.cjs"),
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        devTools: !app.isPackaged,
        spellcheck: false,
      },
    });
    win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    win.webContents.on("will-navigate", (event) => event.preventDefault());
    win.on("close", (event) => {
      if (busy) event.preventDefault();
    });
    ipcMain.handle("keen:connect", async (event, input) => {
      if (
        event.sender !== win.webContents ||
        event.senderFrame !== win.webContents.mainFrame ||
        event.senderFrame.url !== page
      )
        return { ok: false, error: "Untrusted setup request." };
      if (busy) return { ok: false, error: "Setup is already running." };
      busy = true;
      try {
        return await provision(validate(input));
      } catch (e) {
        return { ok: false, error: e.message };
      } finally {
        busy = false;
      }
    });
    win.loadFile(path.join(__dirname, "ui/index.html"));
  });
  app.on("window-all-closed", () => app.quit());
}
