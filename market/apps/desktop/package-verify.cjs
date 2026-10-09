'use strict';
const {Worker}=require('node:worker_threads');
const path=require('node:path');
function verifyPackage(file,info,publicKey) {
  // Hashing a full ZIP takes seconds. Keep it outside the Electron UI thread.
  return new Promise((resolve,reject)=>{
    let received=false;
    const worker=new Worker(`
      const {parentPort,workerData:d}=require('node:worker_threads');
      try {
        const bytes=require('node:fs').readFileSync(d.file);
        if(require('node:crypto').createHash('sha256').update(bytes).digest('hex')!==d.hash)throw Error('Package hash mismatch');
        require(d.verifier).verifyMinisign(bytes,d.signature,d.publicKey,d.version);
        parentPort.postMessage({ok:true});
      } catch(error) { parentPort.postMessage({error:error.message}); }
    `,{eval:true,workerData:{file,hash:info.sha256,signature:info.signature,publicKey,version:info.version,verifier:path.join(__dirname,'minisign.cjs')}});
    worker.once('message',result=>{received=true;if(result.ok)resolve();else reject(Error(result.error));});
    worker.once('error',reject);
    worker.once('exit',code=>{if(!received||code!==0)reject(Error('Package verification worker failed'));});
  });
}
module.exports={verifyPackage};
