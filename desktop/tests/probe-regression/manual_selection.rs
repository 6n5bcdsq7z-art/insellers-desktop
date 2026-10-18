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
