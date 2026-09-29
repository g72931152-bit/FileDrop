import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

const BASE = 'http://127.0.0.1:10000';
function b64url(obj) { return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
async function upload(name, bytes, settings) {
  const res = await fetch(BASE + '/api/upload', { method: 'POST', headers: {
    'Content-Type': 'application/octet-stream',
    'X-File-Name': encodeURIComponent(name),
    'X-File-Type': 'application/octet-stream',
    'X-FileDrop-Settings': b64url(settings),
  }, body: bytes });
  const body = await res.json();
  assert.equal(res.status, 201, JSON.stringify(body));
  return body;
}
async function jget(path, opts={}) { const r=await fetch(BASE+path,{...opts,cache:'no-store'}); let b={}; try{b=await r.json()}catch{} return {r,b}; }
function getSetCookie(res) { const all = res.headers.getSetCookie?.() || []; return all.map(v=>v.split(';')[0]).join('; '); }

const root = await fetch(BASE + '/');
assert.equal(root.status, 200);
assert.match(await root.text(), /FileDrop/);
const health = await fetch(BASE + '/healthz');
assert.equal(health.status, 200);
assert.equal((await health.json()).version, 'v1 (0.15)');
const css = await fetch(BASE + '/styles.css'); assert.equal(css.status,200);
const app = await fetch(BASE + '/app.js'); assert.equal(app.status,200);
const logo = await fetch(BASE + '/assets/filedrop-logo.png'); assert.equal(logo.status,200);
const gallery = await new Promise((resolve,reject)=>http.get(BASE+'/ui-state-gallery.html',r=>resolve(r.statusCode)).on('error',reject));
assert.equal(gallery, 404, 'gallery is intentionally standalone, not served by app');

const small = Buffer.from('FileDrop stress payload — 0.15');
const share = await upload('hello.txt', small, { maxDownloads: 1, expiresMs: 3600000, deleteAfterDownload: false, passwordEnabled: false, ownerName: 'Stress User' });
assert.match(share.shareUrl, /\/\w{8}$/);
let meta = await jget('/api/share/' + share.id); assert.equal(meta.r.status,200); assert.equal(meta.b.originalName,'hello.txt');
let dl = await fetch(BASE + '/api/download/' + share.id); assert.equal(dl.status,200); assert.equal(Buffer.compare(Buffer.from(await dl.arrayBuffer()),small),0);
let gone = await jget('/api/share/' + share.id); assert.ok([404,410].includes(gone.r.status), `unexpected share state ${gone.r.status}`);

const pwShare = await upload('secret.txt', Buffer.from('secret'), { maxDownloads: 2, expiresMs: 3600000, passwordEnabled: true, password: 'test-pass-123', ownerName: 'Password User' });
let wrong = await fetch(BASE+'/api/download/'+pwShare.id); assert.equal(wrong.status,401);
let unlockBad = await fetch(BASE+'/api/unlock/'+pwShare.id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:'bad'})}); assert.equal(unlockBad.status,401);
let unlockGood = await fetch(BASE+'/api/unlock/'+pwShare.id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:'test-pass-123'})}); assert.equal(unlockGood.status,200);
const cookie = getSetCookie(unlockGood); assert.ok(cookie.includes('fd_auth_'));
let pwDl = await fetch(BASE+'/api/download/'+pwShare.id,{headers:{Cookie:cookie}}); assert.equal(pwDl.status,200); await pwDl.arrayBuffer();

const delShare = await upload('burn.txt', Buffer.from('burn'), { maxDownloads: 5, expiresMs: 3600000, deleteAfterDownload: true, passwordEnabled:false, ownerName:'Burn User' });
let delDl = await fetch(BASE+'/api/download/'+delShare.id); assert.equal(delDl.status,200); await delDl.arrayBuffer();
let delGone = await jget('/api/share/'+delShare.id); assert.equal(delGone.r.status,404);

const risky = await upload('installer.exe', Buffer.from('not-an-exe'), { maxDownloads:1, expiresMs:3600000, passwordEnabled:false, ownerName:'Risk User' });
assert.ok(risky.riskFlags?.length);
await (await fetch(BASE+'/api/download/'+risky.id)).arrayBuffer();

// Concurrency/limit race: only one of two simultaneous downloads may reserve a one-download share.
const race = await upload('race.bin', Buffer.alloc(1024*1024,7), { maxDownloads:1, expiresMs:3600000, passwordEnabled:false, ownerName:'Race User' });
const raceResults = await Promise.all([1,2].map(async()=>{
  const r=await fetch(BASE+'/api/download/'+race.id); const buf=await r.arrayBuffer(); return {status:r.status, size:buf.byteLength};
}));
assert.equal(raceResults.filter(x=>x.status===200).length,1,JSON.stringify(raceResults));
assert.ok(raceResults.some(x=>x.status===410 || x.status===404),JSON.stringify(raceResults));

// 64 MiB raw streaming upload; this exercises the dependency-free streaming parser and on-disk path.
const stressBytes = Buffer.alloc(64*1024*1024, 0x5a);
const stress = await upload('64mb.bin', stressBytes, { maxDownloads:1, expiresMs:3600000, passwordEnabled:false, ownerName:'Stream Stress' });
assert.equal(stress.size, stressBytes.length);
const stressDl=await fetch(BASE+'/api/download/'+stress.id); assert.equal(stressDl.status,200); const stressRead=await stressDl.arrayBuffer(); assert.equal(stressRead.byteLength,stressBytes.length);

// Verify server-side 2 GiB hard ceiling without sending 2 GiB over the wire.
const tooLarge = await new Promise((resolve,reject)=>{
  const req=http.request('http://127.0.0.1:10000/api/upload',{method:'POST',headers:{'Content-Length':String(2*1024*1024*1024+1),'Content-Type':'application/octet-stream','X-File-Name':'too-large.bin','X-File-Type':'application/octet-stream','X-FileDrop-Settings':b64url({maxDownloads:1,expiresMs:3600000})}},res=>{resolve(res.statusCode); res.resume();});
  req.on('error',reject); req.end();
});
assert.equal(tooLarge,413);

// Presence/drop loop with two local sessions.
async function heartbeat(userId,nick) {
  const r=await fetch(BASE+'/api/presence/heartbeat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId,nickname:nick,visible:true})});
  assert.equal(r.status,200); return getSetCookie(r);
}
const u1=crypto.randomBytes(18).toString('base64url').slice(0,24), u2=crypto.randomBytes(18).toString('base64url').slice(0,24);
const c1=await heartbeat(u1,'Alice Stress');
const c2=await heartbeat(u2,'Bob Stress');
const people=await fetch(BASE+'/api/people?q=Stress'); assert.equal(people.status,200); const ppl=(await people.json()).people; assert.ok(ppl.length>=2);
const dropShare=await upload('drop.txt',Buffer.from('drop'),{maxDownloads:1,expiresMs:3600000,passwordEnabled:false,ownerName:'Alice Stress'});
const drop=await fetch(BASE+'/api/drop',{method:'POST',headers:{'Content-Type':'application/json','Cookie':c1},body:JSON.stringify({senderId:u1,recipientId:u2,shareId:dropShare.id})});
assert.equal(drop.status,201);
const inbox=await fetch(BASE+'/api/inbox?userId='+encodeURIComponent(u2),{headers:{Cookie:c2}}); assert.equal(inbox.status,200); assert.equal((await inbox.json()).messages.length,1);
await (await fetch(BASE+'/api/download/'+dropShare.id)).arrayBuffer();

console.log('STRESS TEST: PASS');
console.log(JSON.stringify({root:root.status,health:health.status,stream64MiB:stress.size,limit2GiB:tooLarge,concurrentRace:raceResults,presenceDrop:true},null,2));
