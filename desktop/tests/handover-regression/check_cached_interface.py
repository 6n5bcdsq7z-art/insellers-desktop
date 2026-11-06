"""Exercise actual candidate preparation with cached and fresh network bindings."""
from pathlib import Path
import subprocess,tempfile,json,shutil
root=Path(__file__).resolve().parents[2]
s=(root/'src-tauri/src/vpn.rs').read_text()
def block(start):
 end=s.index('{',start)+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
def function(name):return block(s.index('fn '+name+'('))
# Run macOS preparation deterministically on every CI OS. No system networking.
names=['is_hy','is_proxy','path_tag','tune']
if 'fn refresh_physical_binding(' in s:names.extend(['refresh_physical_binding','physical_interface'])
body='\n'.join(function(n) for n in names).replace('#[cfg(target_os = "macos")]','')
loop=block(s.index('for mut cfg in raw_cands {',s.index('async fn xray_candidates('))).replace('#[cfg(target_os = "macos")]','')
body+='''
fn mac_physical_if_when_hijacked()->Option<String>{Some("en7".into())}
fn add_probe_rule(_: &mut Value){}
fn local_inbounds()->Value{json!([])}
fn strip_geo_rules(_: &mut Value){}
fn prepare(cfg:Value,prepared:bool)->Value{
 let raw_cands=vec![cfg];let geo=true;let physical_interface=Some("en7".to_string());
 let mut out:Vec<(String,Value)>=Vec::new();
'''+loop+'''
 out.remove(0).1
}
#[test]fn cached_configuration_uses_current_physical_interface(){
 for kind in ["trojan","vless","vmess","shadowsocks","hysteria2"] {
  let cfg=json!({"outbounds":[{"tag":"proxy","protocol":kind,"streamSettings":{"sockopt":{"interface":"en99","tcpKeepAliveIdle":30}}},{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"interface":"lo0"}}}],"routing":{"rules":[]}});
  let got=prepare(cfg,true);
  assert_eq!(got["outbounds"][0]["streamSettings"]["sockopt"]["interface"],"en7","cached {kind} kept a stale interface");
  assert_eq!(got["outbounds"][0]["streamSettings"]["sockopt"]["tcpKeepAliveIdle"],30);
  assert_eq!(got["outbounds"][1]["streamSettings"]["sockopt"]["interface"],"lo0");
  assert_eq!(got["routing"]["rules"],json!([]));
 }
}
#[test]fn fresh_configuration_uses_current_physical_interface(){
 let cfg=json!({"outbounds":[{"tag":"proxy","protocol":"trojan","streamSettings":{"sockopt":{"interface":"en99"}}}],"routing":{"rules":[]}});
 let got=prepare(cfg,false);
 assert_eq!(got["outbounds"][0]["streamSettings"]["sockopt"]["interface"],"en7");
 assert_eq!(got["routing"]["rules"].as_array().unwrap().len(),1);
}
'''
if 'fn refresh_physical_binding(' in s:
 body+='''
#[test]fn chooses_physical_route_without_retaining_old_vpn_interface(){
 assert_eq!(physical_interface("interface: en7", "Network interfaces: en0"),Some("en7".into()));
 assert_eq!(physical_interface("interface: utun8", "Network interfaces: utun8 en7"),Some("en7".into()));
 assert_eq!(physical_interface("interface: utun8", "Network interfaces: utun8 lo0"),None);
 assert_eq!(physical_interface("", "Network interfaces: en7"),None);
}
#[test]fn missing_network_information_preserves_settings(){
 let mut cfg=json!({"outbounds":[{"protocol":"trojan","streamSettings":{"sockopt":{"interface":"en0"}}}]});let before=cfg.clone();
 refresh_physical_binding(&mut cfg,None);assert_eq!(cfg,before);
}
#[test]fn refreshing_does_not_accumulate_or_change_routing(){
 let mut cfg=json!({"outbounds":[{"protocol":"trojan"}],"routing":{"rules":[{"domain":["example.test"],"outboundTag":"proxy"}]}});
 refresh_physical_binding(&mut cfg,Some("en7"));let once=cfg.clone();refresh_physical_binding(&mut cfg,Some("en7"));assert_eq!(cfg,once);
}
'''
with tempfile.TemporaryDirectory(prefix='vpn-interface-regression-') as td:
 p=Path(td);(p/'src').mkdir();(p/'Cargo.toml').write_text('[package]\nname="vpn-interface-regression"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nserde_json="1"\n');shutil.copyfile(root/'src-tauri/Cargo.lock',p/'Cargo.lock');(p/'src/lib.rs').write_text('use serde_json::{Value,json};\n'+body)
 subprocess.run(['cargo','test','--quiet','--manifest-path',str(p/'Cargo.toml')],check=True)
