"use strict";
function validate(value) {
  if (
    !value ||
    typeof value.url !== "string" ||
    typeof value.code !== "string"
  )
    throw new Error("Enter the instance URL and enrolment code.");
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
  const code = value.code.trim();
  if (!/^kc_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(code))
    throw new Error(
      "Paste the single-use enrolment code KEEN created for this device.",
    );
  return { url: url.origin, code };
}
const messages = {
  10: "The URL or enrolment code is invalid.",
  11: "KEEN did not accept this enrolment. The code may be used or expired: ask your administrator for a new one. Also check the URL, network and certificate trust.",
  12: "This workstation is already enrolled with a different KEEN instance. Ask your administrator to remove its protected configuration first.",
  13: "The protected configuration could not be saved. Check the installation and disk permissions. A stale setup.lock after a crash may need administrator removal.",
  14: "The device was enrolled, but the service could not be started. Check the system service logs, then retry with the same URL and code.",
  15: "Administrator approval is required.",
};
function exitCode(stdout) {
  const s = stdout.trim();
  return /^-?\d+$/.test(s) ? Number(s) : 1;
}
module.exports = { validate, messages, exitCode };
