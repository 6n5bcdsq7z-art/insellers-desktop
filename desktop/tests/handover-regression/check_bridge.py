"""Execute the actual native bridge permission logic with trusted/synthetic clicks."""
from pathlib import Path
import re,subprocess
s=(Path(__file__).resolve().parents[2]/'src-tauri/src/main.rs').read_text()
a=s.index('  var manualConnectUntil = 0;');b=s.index('  window.InsellersNative =',a)
logic=s[a:b].replace('{{','{').replace('}}','}')
connect=re.search(r'    connect: function \(\) \{\{ (.*?) \}\},',s).group(1).replace('{{','{').replace('}}','}')
test=r"""
const assert=require('node:assert/strict');let clock=1000,listener,calls=[];
const Date={now:()=>clock},document={addEventListener:(_,f)=>listener=f};
const inv=(cmd,arg)=>calls.push(arg.user_requested);
LOGIC
function connect(){BODY}
function click(trusted,match){listener({isTrusted:trusted,target:{closest:()=>match}})}
connect();assert.equal(calls.pop(),false);
click(false,true);connect();assert.equal(calls.pop(),false);
click(true,false);connect();assert.equal(calls.pop(),false);
click(true,true);connect();assert.equal(calls.pop(),true);
connect();assert.equal(calls.pop(),false);
click(true,true);clock+=30001;connect();assert.equal(calls.pop(),false);
console.log('actual bridge: automatic, synthetic, unrelated, manual, consumed, expired PASS');
""".replace('LOGIC',logic).replace('BODY',connect)
subprocess.run(['node','-e',test],check=True)
assert 'telemetry::set_trigger("startup"); let _ = vpn_connect_mode(h, false).await;' in s
