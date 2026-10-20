#[path = "../../src-tauri/src/private_file.rs"]
mod private_file;
#[path = "../../src-tauri/src/traffic_probe.rs"]
mod traffic_probe;
mod manual_selection;
include!(concat!(env!("OUT_DIR"), "/helper.rs"));
include!(concat!(env!("OUT_DIR"), "/variants.rs"));
use tokio::io::{AsyncReadExt,AsyncWriteExt};
async fn mock(status:u16, body:usize, stall:bool)->u16 {
 let l=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=l.local_addr().unwrap().port();
 tokio::spawn(async move {let (mut s,_)=l.accept().await.unwrap();let mut req=[0u8;4096];let _=s.read(&mut req).await;
 if stall {tokio::time::sleep(Duration::from_secs(3)).await;return;}
 let head=format!("HTTP/1.1 {status} Test\r\nContent-Length: {body}\r\nConnection: close\r\n\r\n");let _=s.write_all(head.as_bytes()).await;
 let _=s.write_all(&vec![b'x';body]).await;});port
}
async fn sequence(responses:Vec<(u16,usize)>)->u16 {
 let l=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=l.local_addr().unwrap().port();
 tokio::spawn(async move {for (status,body) in responses {let (mut s,_)=l.accept().await.unwrap();let mut req=[0u8;4096];let _=s.read(&mut req).await;
 let head=format!("HTTP/1.1 {status} Test\r\nContent-Length: {body}\r\nConnection: close\r\n\r\n");let _=s.write_all(head.as_bytes()).await;let _=s.write_all(&vec![b'x';body]).await;}});port
}
#[tokio::main]
async fn main(){
 manual_selection::run();
 for (status,size,expected) in [(500,65536,false),(403,65536,false),(200,64,false),(204,0,false),(302,65536,false),(200,32768,true)] {
  let port=mock(status,size,false).await;
  let (ok,_,_,_)=traffic_probe::check_urls(port,32768,Duration::from_secs(2),&["http://fixture.invalid/32k"]).await;
  assert_eq!(ok,expected,"startup traffic: {status}/{size}");
 }
 let port=sequence(vec![(503,65536),(200,32768)]).await;
 let (ok,bytes,_,_)=traffic_probe::check_urls(port,32768,Duration::from_secs(2),&["http://fixture.invalid/primary","http://fixture.invalid/fallback"]).await;
 assert!(ok&&bytes>=32768,"independent fallback must carry real bytes");
 let port=mock(200,0,true).await;
 let (ok,_,elapsed,_)=traffic_probe::check_urls(port,32768,Duration::from_millis(500),&["http://fixture.invalid/stall"]).await;
 assert!(!ok&&elapsed<1500,"global deadline must bound a stalled response");
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
 let port=listener.local_addr().unwrap().port();
 tokio::spawn(async move {
  let (mut socket,_)=listener.accept().await.unwrap();
  let mut request=[0u8;4096];let _=socket.read(&mut request).await;
  socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\nx").await.unwrap();
  tokio::time::sleep(Duration::from_secs(3)).await;
 });
 let (ok,_,elapsed,_)=traffic_probe::check_urls(port,32768,Duration::from_millis(500),&["http://fixture.invalid/stalled-body"]).await;
 assert!(!ok&&elapsed<1500,"headers must not reset the body deadline");
 println!("9 real-traffic startup/fallback/deadline cases PASS");
 for status in [401,403,404,500,502] {let p=mock(status,262144,false).await;let (_,n,e)=get_via(p,"http://probe.invalid/128k",131072,2).await;assert_eq!(n,0,"error body must not count");assert_eq!(e,format!("http {status}"));println!("PASS large HTTP {status} rejected before byte limit");}
 for (status,size,max) in [(204,0,1024),(200,131072,131072),(200,2048,1024)] {let p=mock(status,size,false).await;let (_,n,e)=get_via(p,"http://probe.invalid/test",max,2).await;assert!(e.is_empty(),"{e}");assert!(n>=max||status==204);println!("PASS valid {status} {size} bytes");}
 let p=mock(200,64,false).await;let (_,n,e)=get_via(p,"http://probe.invalid/128k",131072,2).await;assert!(e.is_empty()&&n<131072);println!("PASS short payload retains size for caller rejection");
 let p=mock(200,0,true).await;let (ms,n,e)=get_via(p,"http://probe.invalid/204",1024,1).await;assert!(ms<2500&&n==0&&!e.is_empty());println!("PASS timeout bounded");
 for (name,responses,ok) in [
 ("successful three-stage variant",vec![(204,0),(204,0),(200,131072)],true),
 ("first handshake HTTP error",vec![(500,2048)],false),
 ("second RTT HTTP error",vec![(204,0),(500,2048)],false),
 ("bulk HTTP error",vec![(204,0),(204,0),(500,262144)],false),
 ("bulk short response",vec![(204,0),(204,0),(200,64)],false)] {
 let p=sequence(responses).await;let r=test_variants(vec![json!({"id":"fixture","port":p})],"http://probe.invalid/204","http://probe.invalid/128k",131072).await;assert_eq!(r.len(),1);assert_eq!(r[0]["ok"],ok,"{name}");if !ok {assert!(r[0]["err"].as_str().unwrap().len()>0);}println!("PASS {name}");}
 println!("15 actual-source compiled Rust cases PASS");
}
