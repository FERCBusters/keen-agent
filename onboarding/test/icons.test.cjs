const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
test('platform icon containers contain the supplied artwork at the declared dimensions', () => {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'keen-icons-'));
 try {
  const name=require('../icons.cjs')(dir);
  const png=fs.readFileSync(name+'.png');
  assert.equal(png.readUInt32BE(16),256);assert.equal(png.readUInt32BE(20),256);
  const ico=fs.readFileSync(name+'.ico');
  assert.equal(ico.readUInt16LE(2),1);assert.equal(ico.readUInt16LE(4),1);
  assert.equal(ico[6],0);assert.equal(ico[7],0);
  assert.deepEqual(ico.subarray(ico.readUInt32LE(18)),png);
  const icns=fs.readFileSync(name+'.icns');
  assert.equal(icns.toString('ascii',0,4),'icns');
  assert.equal(icns.readUInt32BE(4),icns.length);
  assert.equal(icns.toString('ascii',8,12),'ic08');
  assert.deepEqual(icns.subarray(16),png);
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
