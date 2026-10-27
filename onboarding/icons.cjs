const fs = require("node:fs"),
  path = require("node:path");
module.exports = function (out) {
  fs.mkdirSync(out, { recursive: true });
  const png = Buffer.from(
    fs.readFileSync(path.join(__dirname, "icon.png.b64"), "utf8").trim(),
    "base64",
  );
  const name = path.join(out, "keen");
  fs.writeFileSync(name + ".png", png);
  const ico = Buffer.alloc(22);
  ico.writeUInt16LE(1, 2);
  ico.writeUInt16LE(1, 4);
  ico.writeUInt16LE(1, 10);
  ico.writeUInt16LE(32, 12);
  ico.writeUInt32LE(png.length, 14);
  ico.writeUInt32LE(22, 18);
  fs.writeFileSync(name + ".ico", Buffer.concat([ico, png]));
  const icns = Buffer.alloc(16);
  icns.write("icns");
  icns.writeUInt32BE(16 + png.length, 4);
  icns.write("ic08", 8);
  icns.writeUInt32BE(8 + png.length, 12);
  fs.writeFileSync(name + ".icns", Buffer.concat([icns, png]));
  return name;
};
