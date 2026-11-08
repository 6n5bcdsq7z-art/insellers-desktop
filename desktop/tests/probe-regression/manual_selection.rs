include!(concat!(env!("OUT_DIR"), "/selection.rs"));

pub fn run() {
    let hy = json!({"outbounds":[{"tag":"hy", "protocol":"hysteria2"}]});
    let reality = json!({"outbounds":[{"tag":"reality", "protocol":"vless", "streamSettings":{"network":"tcp"}}]});
    let http = json!({"outbounds":[{"tag":"http", "protocol":"vless", "streamSettings":{"network":"xhttp"}}]});
    let grpc = json!({"outbounds":[{"tag":"grpc", "protocol":"vless", "streamSettings":{"network":"grpc"}}]});
    assert_eq!(pick_config(json!([hy.clone(),reality.clone()]), "reality")["outbounds"][0]["tag"], "reality");
    assert_eq!(pick_config(json!([reality.clone(),hy.clone()]), "hysteria2")["outbounds"][0]["tag"], "hy");
    assert_eq!(pick_config(json!([hy.clone(),http.clone()]), "xhttp")["outbounds"][0]["tag"], "http");
    for (raw, choice) in [(hy.clone(),"reality"),(reality.clone(),"hysteria2"),(hy.clone(),"xhttp"),(grpc,"reality")] {
        assert!(pick_config(raw, choice).is_null(), "missing {choice} must not select another protocol");
    }
    assert_eq!(pick_config(json!([hy.clone(),reality]), "auto")["outbounds"][0]["tag"], "hy");
    for choice in ["reality","xhttp","hysteria2","amneziawg","cfg:NL-1:xhttp"] { assert!(manual_choice(choice)); }
    for choice in ["", "auto"] { assert!(!manual_choice(choice)); }
    println!("PASS actual Desktop selection: exact protocol retained, missing protocol rejected, AWG manual");

    let choice = "cfg:AUTO|reality|-|chrome|-|nofrag";
    let main = json!({"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.1","port":443,"users":[{"flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"fingerprint":"chrome","publicKey":"a"}}});
    let mut reserve=main.clone(); reserve["tag"]=json!("reserve:NL-2"); reserve["settings"]["vnext"][0]["port"]=json!(8391);
    reserve["streamSettings"]["realitySettings"]["publicKey"]=json!("b");
    let cfg=json!({"outbounds":[main,reserve.clone(),{"tag":"direct","protocol":"freedom"}],"dns":{"servers":["1.1.1.1"]},"routing":{"rules":[{"inboundTag":["probe-in"],"outboundTag":"proxy"}]}});
    let next=same_protocol_reserves(&cfg,choice); assert_eq!(next.len(),1);
    assert_eq!(next[0]["outbounds"][0]["tag"],"reserve:NL-2");
    assert_eq!(next[0]["routing"]["rules"][0]["outboundTag"],"reserve:NL-2");
    assert_eq!(next[0]["dns"],cfg["dns"]);
    assert!(same_protocol_reserves(&next[0],choice).is_empty());
    for pin in ["cfg:NL-1|reality|-|chrome|-|nofrag","reality","anytls",""] { assert!(same_protocol_reserves(&cfg,pin).is_empty()); }
    for pointer in ["/protocol","/streamSettings/network","/streamSettings/security","/streamSettings/realitySettings/fingerprint","/settings/vnext/0/users/0/flow"] {
        let mut bad=cfg.clone(); *bad["outbounds"][1].pointer_mut(pointer).unwrap()=json!("different");
        assert!(same_protocol_reserves(&bad,choice).is_empty(),"{pointer}");
    }
    let mut legacy=cfg.clone();legacy["outbounds"][1]["tag"]=json!("srv:NL-2");assert!(same_protocol_reserves(&legacy,choice).is_empty());
    assert!(same_protocol_reserves(&json!(null),choice).is_empty());
    println!("PASS actual Desktop bounded same-protocol reserves: variant, explicit pins, routing, DNS, no loop");

    let stamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir=std::env::temp_dir().join(format!("insellers-manual-cache-{}-{stamp}",std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let last=dir.join("config.last.json");
    let a="fixture-account-A";let b="fixture-account-B";
    let url="https://fixture.invalid/sub/A";let choice="cfg:NL-1:xhttp";
    assert!(write_selection(&dir,a,url,choice));
    assert_eq!(read_selection(&dir,a),Some((url.into(),choice.into())));
    assert_eq!(read_selection(&dir,b),None);
    assert_eq!(read_selection(&dir,""),None);
    assert!(save_profile(&last,&serde_json::to_vec(&http).unwrap(),a,url,choice));
    assert_eq!(cached_profile(&last,a,url,choice),Some(http.clone()));
    assert_eq!(cached_profile(&last,b,url,choice),None);
    assert_eq!(cached_profile(&last,a,"https://fixture.invalid/sub/B",choice),None);
    assert_eq!(cached_profile(&last,a,url,"cfg:NL-2:xhttp"),None);
    assert_eq!(cached_profile(&last,"",url,choice),None);
    let before=std::fs::read(&last).unwrap();
    assert!(!save_profile(&last,b"invalid json",a,url,choice));
    assert_eq!(std::fs::read(&last).unwrap(),before);
    let old=std::time::SystemTime::now()-std::time::Duration::from_secs(15*86400);
    std::fs::File::open(&last).unwrap().set_modified(old).unwrap();
    assert_eq!(cached_profile(&last,a,url,choice),None);
    std::fs::write(&last,serde_json::to_vec(&http).unwrap()).unwrap();
    assert_eq!(cached_profile(&last,a,url,choice),None); // unbound old versions
    std::fs::write(&last,b"partial").unwrap();
    assert_eq!(cached_profile(&last,a,url,choice),None);
    std::fs::remove_dir_all(dir).unwrap();
    println!("PASS actual Desktop private cache: account, subscription, exact choice, TTL, invalid/legacy data");
}
