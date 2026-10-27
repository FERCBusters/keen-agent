"use strict";
function validate(value) {
  if (
    !value ||
    typeof value.url !== "string" ||
    typeof value.token !== "string"
  )
    throw new Error("Enter the instance URL and token.");
  const raw = value.url.trim();
  if (raw.length > 2048) throw new Error("The instance URL is too long.");
  let url;
  try {
    url = new URL(raw.includes("://") ? raw : "https://" + raw);
  } catch {
    throw new Error("Enter your KEEN instance domain.");
  }
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new Error(
      "Use an HTTPS instance domain without a path, query or credentials.",
    );
  const token = value.token.trim();
  if (!/^[\x21-\x7e]{16,16384}$/.test(token))
    throw new Error("Paste the individual workstation token from KEEN.");
  return { url: url.origin, token };
}
const messages = {
  10: "The URL or token is invalid.",
  11: "KEEN could not verify this connection. Check the URL, token, network and certificate trust, then retry.",
  12: "This workstation already has a different connection. Ask your administrator to rotate its protected configuration.",
  13: "The protected configuration could not be saved. Check the installation and disk permissions. A stale setup.lock after a crash may need administrator removal.",
  14: "Credentials were saved, but the service could not be started. Check the system service logs, then retry with the same URL and token.",
  15: "Administrator approval is required.",
};
function exitCode(stdout) {
  const s = stdout.trim();
  return /^-?\d+$/.test(s) ? Number(s) : 1;
}
module.exports = { validate, messages, exitCode };
