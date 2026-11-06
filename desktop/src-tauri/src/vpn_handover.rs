//! User-initiated macOS Network Extension handover, never process-name killing.
use std::sync::{Arc, Mutex};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service { pub id: String, pub name: String }
pub type Stopped = Arc<Mutex<Vec<Service>>>;
pub trait System {
    fn active(&mut self) -> Result<Vec<Service>, String>;
    fn stop(&mut self, id: &str) -> Result<(), String>;
    fn start(&mut self, id: &str) -> Result<(), String>;
    fn disconnected(&mut self, id: &str) -> Result<bool, String>;
    fn connected(&mut self, id: &str) -> Result<bool, String>;
    fn pause(&mut self);
}
pub fn active_services(text: &str) -> Vec<Service> {
    text.lines().filter_map(|line| {
        if !line.contains("(Connected)") && !line.contains("(Connecting)") { return None; }
        let name = line.split('"').nth(1)?;
        if name.is_empty() || name.to_lowercase().contains("insellers") { return None; }
        let id = line.split_whitespace().find(|s| s.len() == 36 && s.chars().enumerate().all(|(i,c)|
            if matches!(i,8|13|18|23) {c=='-'} else {c.is_ascii_hexdigit()}))?;
        Some(Service{id:id.into(),name:name.into()})
    }).collect()
}
pub fn disconnect(system: &mut impl System, stopped: &Stopped, cancelled: impl Fn() -> bool) -> Result<(), String> {
    let services = system.active()?;
    if services.is_empty() { return Err("Не найдено подключение, которое можно безопасно отключить автоматически".into()); }
    for service in &services {
        if cancelled() { return Err("CANCELLED".into()); }
        // Record before the command: even a timeout may have stopped the service.
        stopped.lock().unwrap().push(service.clone());
        system.stop(&service.id)?;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    for _ in 0..60 {
        if std::time::Instant::now() >= deadline { break; }
        if cancelled() { return Err("CANCELLED".into()); }
        let mut all = true;
        for s in &services { all &= system.disconnected(&s.id)?; }
        if all { return Ok(()); }
        system.pause();
    }
    Err("Другой VPN не завершил отключение. INSELLERS не включён".into())
}
pub fn restore(system: &mut impl System, stopped: &[Service]) -> Result<(), String> {
    if stopped.is_empty() { return Ok(()); }
    let active = system.active()?;
    if active.iter().any(|s| !stopped.iter().any(|old| old.id==s.id)) {
        return Err("Уже включено другое подключение; оно сохранено".into());
    }
    for s in stopped {
        if !active.iter().any(|a| a.id==s.id) { system.start(&s.id)?; }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    for _ in 0..60 {
        if std::time::Instant::now() >= deadline { break; }
        let mut all = true;
        for s in stopped { all &= system.connected(&s.id)?; }
        if all { return Ok(()); }
        system.pause();
    }
    Err("Прежний VPN не подтвердил подключение. Включите его вручную".into())
}
#[cfg(target_os="macos")]
pub struct Mac;
#[cfg(target_os="macos")]
fn scutil(args: &[&str]) -> Result<String,String> {
    use std::{process::{Command,Stdio},time::{Duration,Instant},thread};
    let mut child=Command::new("/usr/sbin/scutil").args(args).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "Не удалось обратиться к VPN macOS".to_string())?;
    let until=Instant::now()+Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_))=>break,
            Ok(None) if Instant::now()<until=>thread::sleep(Duration::from_millis(50)),
            _=>{let _=child.kill();let _=child.wait();return Err("macOS не ответила на запрос переключения VPN".into());}
        }
    }
    let out=child.wait_with_output().map_err(|_| "Не удалось получить состояние VPN macOS".to_string())?;
    if !out.status.success() { return Err("macOS не разрешила переключить другое VPN-подключение".into()); }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
#[cfg(target_os="macos")]
impl System for Mac {
    fn active(&mut self)->Result<Vec<Service>,String>{Ok(active_services(&scutil(&["--nc","list"])?))}
    fn stop(&mut self,id:&str)->Result<(),String>{scutil(&["--nc","stop",id]).map(|_|())}
    fn start(&mut self,id:&str)->Result<(),String>{scutil(&["--nc","start",id]).map(|_|())}
    fn disconnected(&mut self,id:&str)->Result<bool,String>{
        let s=scutil(&["--nc","status",id])?;
        match s.lines().next().map(str::trim) {
            Some("Disconnected")=>Ok(true),
            Some("Connected"|"Connecting"|"Disconnecting"|"Reasserting")=>Ok(false),
            _=>Err("Не удалось подтвердить отключение другого VPN".into()),
        }
    }
    fn connected(&mut self,id:&str)->Result<bool,String>{
        Ok(scutil(&["--nc","status",id])?.lines().next().map(str::trim)==Some("Connected"))
    }
    fn pause(&mut self){std::thread::sleep(std::time::Duration::from_millis(200));}
}
#[cfg(test)]
mod tests {
 use super::*;
 #[derive(Default)]struct Fake {active:Vec<Service>,stop:Vec<String>,start:Vec<String>,fail_stop:bool,stuck:bool}
 impl System for Fake {
  fn active(&mut self)->Result<Vec<Service>,String>{Ok(self.active.clone())}
  fn stop(&mut self,id:&str)->Result<(),String>{self.stop.push(id.into());if !self.stuck {self.active.retain(|s|s.id!=id);}if self.fail_stop {Err("failed".into())}else{Ok(())}}
  fn start(&mut self,id:&str)->Result<(),String>{self.start.push(id.into());self.active.push(Service{id:id.into(),name:"VPN".into()});Ok(())}
  fn disconnected(&mut self,id:&str)->Result<bool,String>{Ok(!self.active.iter().any(|s|s.id==id))}
  fn connected(&mut self,id:&str)->Result<bool,String>{Ok(self.active.iter().any(|s|s.id==id))}
  fn pause(&mut self){}
 }
 fn service()->Service{Service{id:"09C2B009-9062-4656-BE2C-B8E6C78F10B9".into(),name:"incy".into()}}
 fn saved()->Stopped{Arc::new(Mutex::new(Vec::new()))}
 #[test]fn ignores_closed_disconnected_clients_and_invalid_ids(){
  let s=service();let raw=format!("* (Connected) {} VPN \"incy\"\n* (Disconnected) {} VPN \"Happ\"\n* (Connected) {} VPN \"INSELLERS VPN\"\n* (Connected) bad;command VPN \"bad\"",s.id,s.id,s.id);
  assert_eq!(active_services(&raw),vec![s]);
 }
 #[test]fn stops_exact_service_and_restores_after_failure(){let mut f=Fake{active:vec![service()],..Fake::default()};let old=saved();disconnect(&mut f,&old,||false).unwrap();assert!(f.active.is_empty());restore(&mut f,&old.lock().unwrap()).unwrap();assert_eq!(f.start,f.stop);}
 #[test]fn failed_stop_retains_rollback_identity(){let mut f=Fake{active:vec![service()],fail_stop:true,..Fake::default()};let old=saved();assert!(disconnect(&mut f,&old,||false).is_err());assert_eq!(*old.lock().unwrap(),vec![service()]);restore(&mut f,&old.lock().unwrap()).unwrap();assert_eq!(f.start.len(),1);}
 #[test]fn cancellation_before_handover_never_stops(){let mut f=Fake{active:vec![service()],..Fake::default()};assert_eq!(disconnect(&mut f,&saved(),||true),Err("CANCELLED".into()));assert!(f.stop.is_empty());}
 #[test]fn stuck_disconnect_is_failure(){let mut f=Fake{active:vec![service()],stuck:true,..Fake::default()};assert!(disconnect(&mut f,&saved(),||false).is_err());}
 #[test]fn restore_does_not_replace_new_user_connection(){let mut f=Fake{active:vec![Service{id:"another".into(),name:"another".into()}],..Fake::default()};assert!(restore(&mut f,&[service()]).is_err());assert!(f.start.is_empty());}
 #[test]fn cannot_stop_unidentified_tun(){let mut f=Fake::default();assert!(disconnect(&mut f,&saved(),||false).is_err());assert!(f.stop.is_empty());}
}
