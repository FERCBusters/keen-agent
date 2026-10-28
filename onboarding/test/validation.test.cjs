const test = require("node:test"),
  assert = require("node:assert/strict");
const { validate, exitCode } = require("../validation.cjs");
const code = "kc_6f8459a2-2768-41a4-94d5-a0cdcc2d7187.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
test("instance domain and enrolment code are normalised without exposing secrets", () => {
  assert.deepEqual(validate({ url: "keen.example ", code: ` ${code} ` }), {
    url: "https://keen.example",
    code,
  });
  for (const url of [
    "http://keen.example",
    "https://u:secret@keen.example",
    "https://keen.example/path",
    "https://keen.example?token=secret",
    "https://keen.example#token",
  ])
    assert.throws(() => validate({ url, code }));
  for (const bad of [
    "short",
    "ka_6f8459a2-2768-41a4-94d5-a0cdcc2d7187." + "A".repeat(43),
    "ke_6f8459a2-2768-41a4-94d5-a0cdcc2d7187." + "A".repeat(43),
    code + "\u0000",
    code.slice(0, -1) + " ",
  ])
    assert.throws(() => validate({ url: "keen.example", code: bad }));
});
test("missing or malformed helper output cannot imply success", () => {
  assert.equal(exitCode("0\r\n"), 0);
  assert.equal(exitCode("14\n"), 14);
  assert.equal(exitCode("-128"), -128);
  for (const value of ["", "garbage", "0\n11", "NaN"])
    assert.notEqual(exitCode(value), 0);
});
