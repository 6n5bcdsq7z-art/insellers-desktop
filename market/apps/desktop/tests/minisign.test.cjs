const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {verifyMinisign}=require('../minisign.cjs');
const base=path.join(__dirname,'fixtures');
const data=fs.readFileSync(path.join(base,'tauri-package.bin'));
const signature=fs.readFileSync(path.join(base,'tauri-package.sig'),'utf8').trim();
const key=fs.readFileSync(path.join(base,'tauri-package.pub'),'utf8').trim();
test('accept independent Tauri CLI signature and signed version',()=>assert.equal(verifyMinisign(data,signature,key,'1.0.9'),true));
test('reject modified archive, signed version replay, wrong key and modified trusted metadata',()=>{
 const bad=Buffer.from(data);bad[0]^=1;assert.throws(()=>verifyMinisign(bad,signature,key,'1.0.9'));
 assert.throws(()=>verifyMinisign(data,signature,key,'1.0.10'),/version/);
 const lines=Buffer.from(signature,'base64').toString().split('\n');lines[2]=lines[2].replace('1.0.9','1.0.10');assert.throws(()=>verifyMinisign(data,Buffer.from(lines.join('\n')).toString('base64'),key,'1.0.10'),/metadata/);
 const keys=Buffer.from(key,'base64').toString().trim().split('\n');const bytes=Buffer.from(keys[1],'base64');bytes[10]^=1;keys[1]=bytes.toString('base64');assert.throws(()=>verifyMinisign(data,signature,Buffer.from(keys.join('\n')).toString('base64'),'1.0.9'));
});
const {validateMacFeed}=require('../mac-updates.cjs');
function feed(){return {version:'1.0.9',files:{arm64:{url:'https://github.com/6n5bcdsq7z-art/insellers-desktop/releases/download/market-9-abcdef0/INSELLERS-1.0.9-mac-arm64.zip',sha256:'a'.repeat(64),signature,size:100}}};}
test('choose matching Mac architecture and reject downgrade or foreign update location',()=>{
 assert.equal(validateMacFeed(feed(),'arm64','1.0.8').version,'1.0.9');assert.equal(validateMacFeed(feed(),'arm64','1.0.9'),null);
 assert.throws(()=>validateMacFeed(feed(),'x64','1.0.8'));
 const f=feed();f.files.arm64.url='https://evil.test/INSELLERS-1.0.9-mac-arm64.zip';assert.throws(()=>validateMacFeed(f,'arm64','1.0.8'));
});
const {verifyPackage}=require('../package-verify.cjs');
test('verification worker accepts real signed fixture and rejects corrupted metadata',async()=>{
 const info={sha256:require('node:crypto').createHash('sha256').update(data).digest('hex'),signature,version:'1.0.9'};
 await verifyPackage(path.join(base,'tauri-package.bin'),info,key);
 await assert.rejects(verifyPackage(path.join(base,'tauri-package.bin'),{...info,sha256:'a'.repeat(64)},key),/hash/);
});
