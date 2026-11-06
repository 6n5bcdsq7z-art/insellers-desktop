"""Run the actual four-engine startup preparation with a private policy fixture."""
from pathlib import Path
import os,subprocess,tempfile,shutil
root=Path(__file__).resolve().parents[2]
s=(root/'src-tauri/src/vpn.rs').read_text()
def block(start):
 end=s.index('{',start)+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
a=s.index('        let engine = crate::naive::engine(profile,',s.index('if let Some(ref profile) = naive_profile {'))
b=s.index('        if !crate::private_file::write_private',a)
actual=s[a:b]
start=s.index('const AD_DIRECT:');end=s.index('\n];',start)+3
constants=s[start:end]
policy=block(s.index('fn ad_policy(')) if 'fn ad_policy(' in s else ''
fixture=r'''
#![allow(dead_code,unused_variables)]
use serde_json::{json,Value};use std::path::PathBuf;
#[path="NAIVE"]mod naive;
fn now_ms()->u64{1000}
CONSTANTS
POLICY
fn prepare(profile:&Value,dir:PathBuf)->Result<Value,String>{
ACTUAL
Ok(router)
}
fn profile(kind:&str)->Value{
json!({"protocol":kind,"server":"r1.insellers.su","server_port":26443,
"username":if kind=="mieru"{format!("m_{}","a".repeat(62))}else{format!("n_{}","a".repeat(64))},
"password":"b".repeat(64),"uuid":"00000000-0000-4000-8000-000000000001","expires_ms":9000000,
"dns":{"url":"https://vpn.insellers.su/dns-query/","host":"vpn.insellers.su","ip":"192.0.2.80"}})
}
#[test]fn all_four_startup_routers_honor_authoritative_ad_policy(){
 let dir=std::path::Path::new("FIXTURE").to_path_buf();
 std::fs::write(dir.join("ad-hosts.json"),json!({"direct":["libtl.com","tads.me","invalid/path","vpn.insellers.su"],"tunnel":["w.tads.me"]}).to_string()).unwrap();
 for kind in ["naive","tuic","mieru","anytls"] {
  let p=profile(kind);let original=naive::router(&p,now_ms()).unwrap();let got=prepare(&p,dir.clone()).unwrap();
  assert!(got["outbounds"].as_array().unwrap().iter().any(|o|o["tag"]=="direct"&&o["protocol"]=="freedom"),"{kind}: no direct ad route");
  let rules=got["routing"]["rules"].as_array().unwrap();let old=original["routing"]["rules"].as_array().unwrap();
  assert_eq!(&rules[..old.len()],old.as_slice(),"{kind}: safety/DNS rules changed");
  let tunnel=rules.iter().position(|r|r["outboundTag"]=="proxy"&&r["domain"].as_array().map(|a|a.contains(&json!("domain:w.tads.me"))).unwrap_or(false)).expect("missing authoritative tunnel exception");
  let direct=rules.iter().position(|r|r["outboundTag"]=="direct"&&r["domain"].as_array().map(|a|a.contains(&json!("domain:libtl.com"))).unwrap_or(false)).expect("missing direct ad route");
  assert!(tunnel<direct);assert!(!rules[direct].to_string().contains("invalid/path"));assert!(!rules[direct].to_string().contains("domain:vpn.insellers.su"));
  assert_eq!(got["dns"],original["dns"]);assert_eq!(got["outbounds"][0],original["outbounds"][0]);
  if let Ok(bin)=std::env::var("XRAY_TEST_BIN") {
   let path=dir.join(format!("{kind}.json"));std::fs::write(&path,got.to_string()).unwrap();
   let result=std::process::Command::new(bin).args(["run","-test","-config"]).arg(&path).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
   assert!(result.success(),"installed Xray rejected {kind} router");
  }
 }
}
EXTRA_TESTS
'''.replace('NAIVE',str(root/'src-tauri/src/naive.rs')).replace('CONSTANTS',constants).replace('POLICY',policy).replace('ACTUAL',actual)
policy_tests=r'''
#[test]fn complete_empty_policy_revokes_defaults(){
 let dir=std::path::Path::new("FIXTURE").join("empty");std::fs::create_dir_all(&dir).unwrap();
 std::fs::write(dir.join("ad-hosts.json"),r#"{"direct":[],"tunnel":[]}"#).unwrap();
 let (a,t)=ad_policy(&dir);assert!(a.is_empty()&&t.is_empty());
 let p=profile("anytls");assert_eq!(prepare(&p,dir).unwrap(),naive::router(&p,now_ms()).unwrap());
}
#[test]fn absent_or_incomplete_cache_retains_sdk_tunnel_exceptions(){
 let dir=std::path::Path::new("FIXTURE").join("missing");std::fs::create_dir_all(&dir).unwrap();
 for raw in [None,Some("not json"),Some(r#"{"direct":["wrong.example"]}"#)] {
  if let Some(raw)=raw{std::fs::write(dir.join("ad-hosts.json"),raw).unwrap();}
  let (_,t)=ad_policy(&dir);
  for host in ["domain:w.tads.me","domain:sad.adsgram.ai","domain:gigapub.tech"]{assert!(t.contains(&host.to_owned()));}
 }
}
#[test]fn invalid_domains_ips_and_own_domains_cannot_be_direct(){
 let dir=std::path::Path::new("FIXTURE").join("validation");std::fs::create_dir_all(&dir).unwrap();
 std::fs::write(dir.join("ad-hosts.json"),json!({"direct":[" LIBTL.COM ","libtl.com","127.0.0.1","bad..host","*.example.test","-bad.example","example.test-","insellers.su","bot.insellers.su",4],"tunnel":["W.TADS.ME","w.tads.me"]}).to_string()).unwrap();
 let (a,t)=ad_policy(&dir);assert_eq!(a,vec!["domain:libtl.com"]);assert_eq!(t,vec!["domain:w.tads.me"]);
}
''' if policy else ''
fixture=fixture.replace('EXTRA_TESTS',policy_tests)
with tempfile.TemporaryDirectory(prefix='vpn-ad-policy-') as td:
 p=Path(td);(p/'fixture').mkdir();(p/'Cargo.toml').write_text('[package]\nname="insellers-naive-regression"\nversion="1.0.0"\nedition="2021"\n[dependencies]\nserde_json="1"\nurl="2"\n[lib]\npath="lib.rs"\n')
 shutil.copyfile(root/'tests/naive-regression/Cargo.lock',p/'Cargo.lock')
 (p/'lib.rs').write_text(fixture.replace('FIXTURE',str(p/'fixture')))
 subprocess.run(['cargo','test','--locked','--quiet','--manifest-path',str(p/'Cargo.toml'),'--lib'],check=True)
