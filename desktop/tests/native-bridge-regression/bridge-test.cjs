'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(process.argv[2],'utf8');
function setup(origin){const intervals=[],location={origin,host:new URL(origin).host,href:origin+'/app'};
 const document={visibilityState:'visible',readyState:'complete',title:'',body:{innerText:''},getElementById:()=>({}),addEventListener:()=>{}};
 const ctx={window:{},location,document,URL,navigator:{userActivation:{isActive:true}},sessionStorage:{getItem:()=>null,setItem:()=>{},removeItem:()=>{}},performance:{getEntriesByType:()=>[]},setTimeout:()=>{},setInterval:f=>intervals.push(f),Date,JSON,encodeURIComponent};
 ctx.window.addEventListener=()=>{};ctx.window.open=()=>{};vm.createContext(ctx);vm.runInContext(source,ctx);return{ctx,location,intervals};}
let n=0;
for(const origin of ['https://ads.example','http://vpn.insellers.su','https://vpn.insellers.su:444']){const s=setup(origin);assert.strictEqual(s.ctx.window.InsellersNative,undefined);assert.equal(s.intervals.length,0);n++;}
const s=setup('https://vpn.insellers.su'),bridge=s.ctx.window.InsellersNative;
assert(bridge);assert.equal(bridge.getToken(),'fixture.token.value');n++;
const cases=[['disconnect','vpn_disconnect',[]],['connect','vpn_connect',[]],['login','login',[]],['setToken','set_token',['fixture.token.value']],['checkUpdate','check_update',[]],['setPref','set_pref',['reconnect',true]],['setTheme','set_theme',['light']],['setLang','set_lang',['en']],['probe','probe',[]],['probeFunnel','probe_funnel',[]]];
let nonce=null;
for(const [method,cmd,args]of cases){bridge[method](...args);const u=new URL(s.location.href,'https://vpn.insellers.su');assert.equal(u.pathname,'/__native/'+cmd);assert(/^[0-9a-f]{64}$/.test(u.searchParams.get('n')));if(nonce===null)nonce=u.searchParams.get('n');assert.equal(u.searchParams.get('n'),nonce);assert.doesNotThrow(()=>JSON.parse(u.searchParams.get('a')));n++;}
s.intervals[0]();assert.equal(new URL(s.location.href,'https://vpn.insellers.su').pathname,'/__native/page_alive');assert.equal(new URL(s.location.href,'https://vpn.insellers.su').searchParams.get('n'),nonce);n++;
console.log(n+' actual-generated bridge/origin/watchdog checks PASS');
