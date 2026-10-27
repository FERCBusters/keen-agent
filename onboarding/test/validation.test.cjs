const test = require("node:test"),
  assert = require("node:assert/strict");
const { validate, exitCode } = require("../validation.cjs");
test("instance domain and token are normalised without exposing secrets", () => {
  assert.deepEqual(
    validate({ url: "keen.example ", token: " 0123456789abcdef " }),
    { url: "https://keen.example", token: "0123456789abcdef" },
  );
  for (const url of [
    "http://keen.example",
    "https://u:secret@keen.example",
    "https://keen.example/path",
    "https://keen.example?token=secret",
    "https://keen.example#token",
  ])
    assert.throws(() => validate({ url, token: "0123456789abcdef" }));
  for (const token of ["short", "0123456789 abcdef", "0123456789abcdef\u0000"])
    assert.throws(() => validate({ url: "keen.example", token }));
});
test("missing or malformed helper output cannot imply success", () => {
  assert.equal(exitCode("0\r\n"), 0);
  assert.equal(exitCode("14\n"), 14);
  assert.equal(exitCode("-128"), -128);
  for (const value of ["", "garbage", "0\n11", "NaN"])
    assert.notEqual(exitCode(value), 0);
});
