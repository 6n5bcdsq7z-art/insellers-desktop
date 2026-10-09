'use strict';
const crypto = require('node:crypto');
function verifyMinisign(data, signature, publicKey, expectedVersion) {
  const keyLines = Buffer.from(publicKey, 'base64').toString('utf8').trim().split(/\r?\n/);
  const lines = Buffer.from(signature, 'base64').toString('utf8').trim().split(/\r?\n/);
  if (keyLines.length !== 2 || lines.length !== 4 || !lines[2].startsWith('trusted comment: ')) throw Error('Invalid signature format');
  const key = Buffer.from(keyLines[1], 'base64');
  const signed = Buffer.from(lines[1], 'base64');
  if (key.length !== 42 || signed.length !== 74 || key.subarray(0,2).toString() !== 'Ed'
      || !crypto.timingSafeEqual(key.subarray(2,10), signed.subarray(2,10))) throw Error('Invalid signing key');
  const algorithm = signed.subarray(0,2).toString();
  if (algorithm !== 'ED') throw Error('Unsupported signature algorithm');
  const pub = crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key.subarray(10)]),format:'der',type:'spki'});
  const payload = algorithm === 'ED' ? Buffer.from(require('blakejs').blake2b(data, null, 64)) : data;
  if (!crypto.verify(null, payload, pub, signed.subarray(10))) throw Error('Package signature mismatch');
  const comment = Buffer.from(lines[2].slice('trusted comment: '.length));
  if (!crypto.verify(null, Buffer.concat([signed.subarray(10), comment]), pub, Buffer.from(lines[3], 'base64'))) throw Error('Signature metadata mismatch');
  if (expectedVersion) {
    const version = /(?:^|\t)version:([^\t]+)(?:\t|$)/.exec(comment.toString());
    if (!version || version[1] !== expectedVersion) throw Error('Signed version mismatch');
  }
  return true;
}
module.exports = { verifyMinisign };
