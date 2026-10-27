const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const { JSDOM } = require("jsdom");
const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
const script = fs.readFileSync(
  path.join(__dirname, "../ui/renderer.js"),
  "utf8",
);
for (const ok of [true, false])
  test(`setup ${ok ? "success clears token" : "failure remains editable and inert"}`, async () => {
    const dom = new JSDOM(html, { runScripts: "outside-only" }),
      w = dom.window,
      d = w.document;
    let resolve, seen;
    w.keenSetup = {
      connect: (input) => {
        seen = { ...input };
        return new Promise((r) => {
          resolve = r;
        });
      },
    };
    w.eval(script);
    d.getElementById("url").value = "keen.example";
    d.getElementById("token").value = "0123456789abcdef";
    d.getElementById("setup").dispatchEvent(
      new w.Event("submit", { cancelable: true }),
    );
    assert.equal(d.getElementById("connect").disabled, true);
    assert.deepEqual(seen, { url: "keen.example", token: "0123456789abcdef" });
    resolve(
      ok ? { ok: true } : { ok: false, error: "<img src=x onerror=alert(1)>" },
    );
    await new Promise((r) => setImmediate(r));
    assert.equal(d.getElementById("connect").disabled, false);
    if (ok) {
      assert.equal(d.getElementById("token").value, "");
      assert.equal(d.getElementById("setup").hidden, true);
      assert.equal(d.getElementById("complete").hidden, false);
    } else {
      assert.equal(d.getElementById("setup").hidden, false);
      assert.equal(d.getElementById("status").querySelector("img"), null);
      assert.match(d.getElementById("status").textContent, /<img/);
    }
    dom.window.close();
  });
