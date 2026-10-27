// Generate explicit WiX components for the packaged Electron tree (WiX 4+).
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const root = path.resolve(process.argv[2]),
  output = process.argv[3];
const esc = (s) =>
  s
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
const id = (prefix, s) =>
  prefix + crypto.createHash("sha256").update(s).digest("hex").slice(0, 24);
const refs = [];
function walk(dir, rel = "") {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((entry) => {
      const key = rel + "/" + entry.name,
        full = path.join(dir, entry.name);
      if (entry.isDirectory())
        return `<Directory Id="${id("D", key)}" Name="${esc(entry.name)}">${walk(full, key)}</Directory>`;
      if (!entry.isFile())
        throw new Error("Unexpected link in Windows application tree");
      const component = id("C", key);
      refs.push(`<ComponentRef Id="${component}"/>`);
      const shortcut =
        rel === "" && entry.name === "keen-setup.exe"
          ? '<Shortcut Id="SetupShortcut" Directory="ProgramMenuFolder" Name="KEEN Setup" Advertise="yes"/>'
          : "";
      return `<Component Id="${component}" Guid="*"><File Id="${id("F", key)}" Source="${esc(full)}" Name="${esc(entry.name)}" KeyPath="yes">${shortcut}</File></Component>`;
    })
    .join("\n");
}
const body = walk(root);
fs.writeFileSync(
  output,
  `<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment><DirectoryRef Id="SETUPFOLDER">${body}</DirectoryRef><ComponentGroup Id="SetupUI">${refs.join("")}</ComponentGroup></Fragment></Wix>`,
);
