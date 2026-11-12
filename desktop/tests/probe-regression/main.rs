#[path = "../../src-tauri/src/private_file.rs"]
mod private_file;
#[path = "../../src-tauri/src/traffic_probe.rs"]
mod traffic_probe;
mod manual_selection;
mod cancellation;
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
 cancellation::run();
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
 let slow=listener.local_addr().unwrap().port();
 tokio::spawn(async move {
  let (mut socket,_)=listener.accept().await.unwrap();let mut request=[0u8;4096];let _=socket.read(&mut request).await;
  tokio::time::sleep(Duration::from_millis(800)).await;
  let _=socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\n").await;
  let _=socket.write_all(&vec![b'x';32768]).await;
 });
 let bad=mock(503,65536,false).await;
 let urls=[format!("http://127.0.0.1:{slow}/slow"),format!("http://127.0.0.1:{bad}/bad")];
 let (ok,bytes,elapsed,_)=traffic_probe::check_routed_urls(32768,Duration::from_millis(1200),&[&urls[0],&urls[1]]).await;
 assert!(ok&&bytes>=32768&&elapsed<1500,"healthy primary must keep the full deadline when secondary fails");
 println!("PASS slow healthy primary survives failed secondary within original deadline");
 let stalled=mock(200,0,true).await;
 let healthy=mock(200,32768,false).await;
 let urls=[format!("http://127.0.0.1:{stalled}/stall"),format!("http://127.0.0.1:{healthy}/healthy")];
 let (ok,bytes,elapsed,_)=traffic_probe::check_routed_urls(32768,Duration::from_millis(1200),&[&urls[0],&urls[1]]).await;
 assert!(ok&&bytes>=32768&&elapsed<1000,"stalled primary must not consume fallback deadline");
 println!("PASS fallback starts before stalled primary consumes deadline");
 let short1=mock(200,20000,false).await;let short2=mock(200,20000,false).await;
 let urls=[format!("http://127.0.0.1:{short1}/short"),format!("http://127.0.0.1:{short2}/short")];
 let (ok,bytes,_,_)=traffic_probe::check_routed_urls(32768,Duration::from_secs(2),&[&urls[0],&urls[1]]).await;
 assert!(!ok&&bytes==20000,"two partial responses must never count as useful payload");
 println!("PASS racing short responses do not add up to success");
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let partial=listener.local_addr().unwrap().port();
 tokio::spawn(async move {
  let (mut socket,_)=listener.accept().await.unwrap();let mut buf=[0u8;4096];let _=socket.read(&mut buf).await;
  let _=socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\nx").await;
  tokio::time::sleep(Duration::from_secs(2)).await;
 });
 let bad=mock(503,32768,false).await;
 let urls=[format!("http://127.0.0.1:{partial}/partial"),format!("http://127.0.0.1:{bad}/bad")];
 let (ok,bytes,_,_)=traffic_probe::check_routed_urls(32768,Duration::from_millis(500),&[&urls[0],&urls[1]]).await;
 assert!(!ok&&bytes==1,"global deadline must retain actual partial byte evidence");
 println!("PASS deadline preserves partial byte evidence");
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();
 let worker=tokio::spawn(async move {
  let (mut socket,_)=listener.accept().await.unwrap();let mut buf=[0u8;4096];let _=socket.read(&mut buf).await;
  let closed=tokio::time::timeout(Duration::from_secs(1),socket.read(&mut buf)).await.unwrap().unwrap();
  assert_eq!(closed,0,"cancelled request leaked socket");
 });
 let url=format!("http://127.0.0.1:{port}/stall");
 assert!(tokio::time::timeout(Duration::from_millis(150),traffic_probe::check_routed_urls(32768,Duration::from_secs(6),&[&url])).await.is_err());
 worker.await.unwrap();println!("PASS cancellation closes blocked Desktop request");
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
 // A real stalled bulk body must remain failed. A fresh complete small body
 // distinguishes slow useful traffic from an unavailable route.
 let l=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=l.local_addr().unwrap().port();
 tokio::spawn(async move {let (mut s,_)=l.accept().await.unwrap();let mut request=[0u8;4096];let _=s.read(&mut request).await;
  s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n\r\n").await.unwrap();
  s.write_all(&vec![b'x';65536]).await.unwrap();tokio::time::sleep(Duration::from_secs(3)).await;});
 let bulk=traffic_probe::check_urls(port,262144,Duration::from_millis(200),&["http://fixture.invalid/bulk"]).await;
 assert!(!bulk.0&&bulk.1>=32768&&bulk.3=="timeout","bulk failure must preserve actual progress");
 let small=mock(200,32768,false).await;
 assert!(traffic_probe::partial_timeout_is_slow_urls(small,bulk.1,&bulk.3,Duration::from_secs(1),&["http://fixture.invalid/small"]).await);
 for (status,size) in [(204,0),(500,65536),(200,64),(302,65536)] {
  let small=mock(status,size,false).await;
  assert!(!traffic_probe::partial_timeout_is_slow_urls(small,bulk.1,"timeout",Duration::from_secs(1),&["http://fixture.invalid/small"]).await,"invalid small response must not keep route: {status}/{size}");
 }
 for (received,reason) in [(0,"timeout"),(16384,"timeout"),(65536,"http 403"),(65536,"short"),(65536,"core")] {
  let small=mock(200,32768,false).await;
  assert!(!traffic_probe::partial_timeout_is_slow_urls(small,received,reason,Duration::from_secs(1),&["http://fixture.invalid/small"]).await,"denial/no progress/closed body must retain failure");
 }
 let stalled_small=mock(200,32768,true).await;
 assert!(!traffic_probe::partial_timeout_is_slow_urls(stalled_small,bulk.1,"timeout",Duration::from_millis(200),&["http://fixture.invalid/small"]).await,"a stalled small transfer must retain failure");
 println!("11 partial-progress/complete-small-body/denial cases PASS; bulk checks unchanged");
 for (status,size,expected) in [(204,0,false),(500,65536,false),(200,64,false),(302,65536,false),(200,32768,true)] {
  let port=mock(status,size,false).await;
  let url=format!("http://127.0.0.1:{port}/routed");
  let (ok,_,_,_)=traffic_probe::check_routed_urls(32768,Duration::from_secs(2),&[&url]).await;
  assert_eq!(ok,expected,"routed traffic: {status}/{size}");
 }
 let primary=mock(503,65536,false).await;
 let fallback=mock(200,32768,false).await;
 let urls=[format!("http://127.0.0.1:{primary}/routed"),format!("http://127.0.0.1:{fallback}/routed")];
 let (ok,bytes,_,_)=traffic_probe::check_routed_urls(32768,Duration::from_secs(2),&[&urls[0],&urls[1]]).await;
 assert!(ok&&bytes>=32768,"routed independent fallback must carry real bytes");
 let stalled=mock(200,0,true).await;
 let url=format!("http://127.0.0.1:{stalled}/routed");
 let (ok,_,elapsed,_)=traffic_probe::check_routed_urls(32768,Duration::from_millis(500),&[&url]).await;
 assert!(!ok&&elapsed<1500,"routed response deadline must be bounded");
 println!("7 system-route payload/fallback/deadline cases PASS (not an OS TUN test)");
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
