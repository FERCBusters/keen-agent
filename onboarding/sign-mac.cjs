"use strict";
(async () => {
  const { sign } = await import("@electron/osx-sign");
  if (!process.env.APPLICATION_IDENTITY)
    throw new Error("APPLICATION_IDENTITY required");
  await sign({
    app: process.argv[2],
    identity: process.env.APPLICATION_IDENTITY,
    platform: "darwin",
    optionsForFile: () => ({
      hardenedRuntime: true,
      entitlements: require("node:path").resolve(
        __dirname,
        "../packaging/macos/setup-entitlements.plist",
      ),
    }),
  });
})().catch(() => {
  console.error("Signing the setup app failed.");
  process.exitCode = 1;
});
