'use strict';
const { EventEmitter, once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { Readable } = require('node:stream');
const semver = require('semver');
const { verifyMinisign } = require('./minisign.cjs');
const run = promisify(execFile);
const FEED = 'https://github.com/6n5bcdsq7z-art/insellers-desktop/releases/latest/download/latest-mac-signed.json';
const PUBLIC_KEY = 'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDM4RDRDMDUwRjk3MjNDMzkKUldRNVBITDVVTURVT0FWRmQyVFRpNi9BR05oWnBtODhzeVJxNThnR0RnZVkzZkdzWERxMmRhU0wK';
function validateMacFeed(feed, arch, current) {
  if (!semver.valid(feed.version) || !['arm64','x64'].includes(arch)) throw Error('Invalid version or architecture');
  if (!semver.gt(feed.version, current)) return null;
  const file = feed.files && feed.files[arch];
  if (!file || !/^[a-f0-9]{64}$/.test(file.sha256) || typeof file.signature !== 'string' || file.signature.length > 2048
      || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > 512*1024*1024) throw Error('Invalid update metadata');
  const url = new URL(file.url);
  if (url.origin !== 'https://github.com' || url.username || url.password
      || !url.pathname.startsWith('/6n5bcdsq7z-art/insellers-desktop/releases/download/market-')
      || path.basename(url.pathname) !== `INSELLERS-${feed.version}-mac-${arch}.zip`) throw Error('Invalid update URL');
  return { ...file, version: feed.version };
}
class SignedMacUpdater extends EventEmitter {
  constructor({ app, net }) { super(); this.app=app;this.net=net;this.info=null;this.stage=null; }
  async checkForUpdates() {
    try {
      const response=await this.net.fetch(FEED,{signal:AbortSignal.timeout(20000)});
      if(!response.ok) throw Error('Update feed unavailable');
      const reader=response.body.getReader();let size=0;const parts=[];
      try { for (;;) { const {done,value}=await reader.read(); if(done) break;size+=value.byteLength;if(size>65536) throw Error('Oversized update feed');parts.push(Buffer.from(value)); } }
      finally { reader.releaseLock(); }
      const info=validateMacFeed(JSON.parse(Buffer.concat(parts).toString('utf8')),process.arch,this.app.getVersion());
      this.info=info;
      if(info) this.emit('update-available',info);else this.emit('update-not-available');
      return {updateInfo:info};
    } catch(error) {this.emit('error',error);throw error;}
  }
  async downloadUpdate() {
    let stage;
    try {
      if(!this.info) throw Error('No update selected');
      const info={...this.info};
      stage=await fs.promises.mkdtemp(path.join(os.tmpdir(),'insellers-update-'));
      const zip=path.join(stage,'update.zip');
      const response=await this.net.fetch(info.url,{signal:AbortSignal.timeout(20*60*1000)});
      if(!response.ok) throw Error('Download failed');
      const output=fs.createWriteStream(zip,{mode:0o600});let total=0;
      // pipeline propagates network, file and hash/size failures; no partial ZIP is installed.
      const {Transform}=require('node:stream');
      const counter=new Transform({transform:(chunk,_encoding,callback)=>{
        total+=chunk.length;if(total>info.size){callback(Error('Unexpected package size'));return;}
        this.emit('download-progress',{percent:100*total/info.size});callback(null,chunk);
      }});
      await require('node:stream/promises').pipeline(Readable.fromWeb(response.body),counter,output);
      if(total!==info.size) throw Error('Incomplete package');
      const bytes=await fs.promises.readFile(zip);
      if(crypto.createHash('sha256').update(bytes).digest('hex')!==info.sha256) throw Error('Package hash mismatch');
      verifyMinisign(bytes,info.signature,PUBLIC_KEY,info.version);
      await run('/usr/bin/ditto',['-x','-k',zip,stage]);
      const bundle=path.join(stage,'INSELLERS.app');
      const plist=path.join(bundle,'Contents','Info.plist');
      const id=(await run('/usr/libexec/PlistBuddy',['-c','Print :CFBundleIdentifier',plist])).stdout.trim();
      const version=(await run('/usr/libexec/PlistBuddy',['-c','Print :CFBundleShortVersionString',plist])).stdout.trim();
      if(id!=='su.insellers.market'||version!==info.version) throw Error('Wrong application package');
      this.stage={root:stage,bundle,version};
      this.emit('update-downloaded',info);
      return [zip];
    } catch(error) {if(stage) await fs.promises.rm(stage,{recursive:true,force:true});this.emit('error',error);throw error;}
  }
  quitAndInstall() {void this.install().catch(error=>this.emit('error',error));}
  async install() {
    if(!this.stage) throw Error('No verified update');
    const current=path.dirname(path.dirname(path.dirname(await fs.promises.realpath(process.execPath))));
    if(path.basename(current)!=='INSELLERS.app') throw Error('Unexpected application location');
    await fs.promises.access(path.dirname(current),fs.constants.W_OK);
    try { await fs.promises.access(current+'.insellers-backup'); throw Error('Previous update backup needs recovery'); }
    catch(error) { if(error.code !== 'ENOENT') throw error; }
    const helper=path.join(this.stage.root,'install.sh');
    await fs.promises.writeFile(helper,`#!/bin/bash
set -eu
market_pid="$1"
market_current="$2"
market_next="$3"
market_stage="$4"
market_backup="$market_current.insellers-backup"
market_wait=0
while kill -0 "$market_pid" 2>/dev/null; do
  market_wait=$((market_wait+1))
  [ "$market_wait" -lt 150 ] || exit 1
  sleep 0.2
done
[ ! -e "$market_backup" ] || exit 1
if /bin/mv "$market_current" "$market_backup"; then
  if /bin/mv "$market_next" "$market_current"; then
    if /usr/bin/open "$market_current"; then
      /bin/rm -rf "$market_backup"
      /bin/rm -rf "$market_stage"
      exit 0
    fi
    /bin/mv "$market_current" "$market_next"
  fi
  /bin/mv "$market_backup" "$market_current"
fi
/usr/bin/open "$market_current"
exit 1
`,{mode:0o700});
    const child=spawn('/bin/bash',[helper,String(process.pid),current,this.stage.bundle,this.stage.root],{detached:true,stdio:'ignore'});
    await once(child,'spawn');child.unref();this.app.quit();
  }
}
module.exports={SignedMacUpdater,validateMacFeed};
