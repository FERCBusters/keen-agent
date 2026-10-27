"use strict";
const path = require("node:path"),
  fs = require("node:fs/promises");
(async () => {
  const { packager } = await import("@electron/packager");
  const { flipFuses, FuseVersion, FuseV1Options } =
    await import("@electron/fuses");
  const platform = process.env.SETUP_PLATFORM || process.platform;
  const arch = process.env.SETUP_ARCH || process.arch;
  const icon = require("./icons.cjs")(
    path.resolve(__dirname, "../dist/setup-icons"),
  );
  const options = {
    dir: __dirname,
    out: path.resolve(__dirname, "../dist/onboarding"),
    name: "KEEN Setup",
    executableName: "keen-setup",
    appBundleId: "net.keen.setup",
    platform,
    arch,
    icon:
      icon +
      (platform === "darwin"
        ? ".icns"
        : platform === "win32"
          ? ".ico"
          : ".png"),
    asar: true,
    overwrite: true,
    prune: true,
    ignore: [
      /^\/test(?:\/|$)/,
      /^\/package\.cjs$/,
      /^\/package-lock\.json$/,
      /^\/(sign-mac|wix-files|icons)\.cjs$/,
      /^\/icon\.png\.b64$/,
    ],
    afterCopy: [
      async ({ buildPath }) => {
        const p = path.join(buildPath, "package.json");
        const j = JSON.parse(await fs.readFile(p));
        delete j.devDependencies;
        delete j.scripts;
        await fs.writeFile(p, JSON.stringify(j));
      },
    ],
    afterComplete: [
      async ({ buildPath, platform: p }) => {
        const target =
          p === "darwin"
            ? path.join(buildPath, "KEEN Setup.app")
            : path.join(
                buildPath,
                p === "win32" ? "keen-setup.exe" : "keen-setup",
              );
        await flipFuses(target, {
          version: FuseVersion.V1,
          [FuseV1Options.RunAsNode]: false,
          [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
          [FuseV1Options.EnableNodeCliInspectArguments]: false,
          [FuseV1Options.OnlyLoadAppFromAsar]: true,
        });
      },
    ],
  };
  // Sign after fuse changes in the platform packaging scripts.
  const dirs = await packager(options);
  console.log(dirs.join("\n"));
})().catch((error) => {
  console.error("Setup app packaging failed:", error.message);
  process.exitCode = 1;
});
