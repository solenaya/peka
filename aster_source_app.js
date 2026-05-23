/* =====================================================================
   ASTER — application logic
   A trauma-informed decision companion for frontline professionals
   who suspect child abuse. Built against SAFV_Requirements_Specification.

   SAFETY & SOURCING NOTES (read before editing):
   - This app NEVER reproduces the proprietary SSSG/CARG instruments.
     It is *structured around* the publicly documented Singapore framework,
     signs/symptoms, and escalation pathway, and points trained users to
     the official tools. (F-22, F-23, spec §3 "Critical IP / safety guardrail")
   - The risk indication is produced by a TRANSPARENT, DETERMINISTIC rules
     engine — never an LLM. It is explainable and reproducible. (AI-1)
   - Emergency numbers are hard-coded and were verified against official
     sources (May 2026):
        Police emergency call: 999
        Police emergency SMS:  70999  <-- (was 71999 until 1 Oct 2024; SPF
                                            discontinued 71999. Verified.)
        NAVH 24h helpline:     1800-777-0000
   - A "Low" result NEVER reads as "all clear / do nothing." (spec §12.3)
   - All case data is encrypted on-device (WebCrypto AES-GCM, key from a
     passphrase via PBKDF2). The provider stores only ciphertext. (F-1a, NF-1)
   ===================================================================== */

'use strict';

/* ----------------------------------------------------------------------
   0. EMERGENCY CONSTANTS — single source of truth, verified.
   ---------------------------------------------------------------------- */
const EMERGENCY = {
  police_call: '999',
  police_sms:  '70999',     // verified current (SPF, from 1 Oct 2024)
  navh:        '1800-777-0000',
  navh_tel:    '18007770000'
};

/* ----------------------------------------------------------------------
   1. CRYPTO LAYER  (zero-knowledge, on-device)  — F-1a, NF-1, NF-3
   Real WebCrypto. The passphrase derives an AES-GCM key via PBKDF2.
   The "server" here is localStorage standing in for a thin sync endpoint
   that only ever sees ciphertext — exactly mirroring the real architecture
   so the privacy claim is demonstrable in the demo (spec §9, §11 crit 4).
   ---------------------------------------------------------------------- */
const Crypto = {
  enc: new TextEncoder(), dec: new TextDecoder(),
  b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); },
  unb64(s){ return Uint8Array.from(atob(s), c => c.charCodeAt(0)); },

  async deriveKey(passphrase, salt){
    const base = await crypto.subtle.importKey(
      'raw', this.enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt, iterations:250000, hash:'SHA-256' },
      base, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
  },
  async encrypt(key, plainObj){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = this.enc.encode(JSON.stringify(plainObj));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, data);
    return this.b64(iv) + ':' + this.b64(ct);
  },
  async decrypt(key, blob){
    const [ivB, ctB] = blob.split(':');
    const pt = await crypto.subtle.decrypt(
      {name:'AES-GCM', iv:this.unb64(ivB)}, key, this.unb64(ctB));
    return JSON.parse(this.dec.decode(pt));
  },
  randSalt(){ return crypto.getRandomValues(new Uint8Array(16)); },
  // human-readable recovery code (F-1b): groups of letters, no ambiguous chars
  recoveryCode(){
    const a='ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    let g=()=>Array.from({length:4},()=>a[Math.floor(Math.random()*a.length)]).join('');
    return `${g()}-${g()}-${g()}`;
  }
};

/* ----------------------------------------------------------------------
   2. "SERVER" — stand-in for the thin zero-knowledge sync endpoint.
   Stores ONLY: account handle, salt, a verification artifact, and an
   opaque ciphertext blob. It can never read case data. (NF-1, NF-1a)
   In production this is a backend-as-a-service; here, localStorage proves
   the same property: try to read it and you get ciphertext.
   ---------------------------------------------------------------------- */
const Server = {
  K:'aster_zk_store_v1',
  read(){ try{ return JSON.parse(localStorage.getItem(this.K)||'{}'); }catch{ return {}; } },
  write(o){ localStorage.setItem(this.K, JSON.stringify(o)); },
  getAccount(handle){ return this.read()[handle] || null; },
  putAccount(handle, rec){ const s=this.read(); s[handle]=rec; this.write(s); },
  deleteAccount(handle){ const s=this.read(); delete s[handle]; this.write(s); },
};

/* ----------------------------------------------------------------------
   3. SESSION — the unlocked client. Holds the key only in memory.
   A "fast re-unlock" PIN (F-2) is stored locally wrapping the salt+verify,
   simulating WebAuthn/platform-authenticator on a trusted device.
   ---------------------------------------------------------------------- */
const Session = {
  handle:null, key:null, _pass:null, journal:[], profile:{role:null}, didAssess:false, idleTimer:null,
  TRUSTED_K:'aster_trusted_device_v1',  // local-only fast re-unlock record
  trusted(){ try{return JSON.parse(localStorage.getItem(this.TRUSTED_K)||'null');}catch{return null;} },
  setTrusted(o){ localStorage.setItem(this.TRUSTED_K, JSON.stringify(o)); },
  clearTrusted(){ localStorage.removeItem(this.TRUSTED_K); },
  lock(){ this.key=null; this.handle=null; this._pass=null; this.journal=[]; this.profile={role:null}; this.didAssess=false; clearTimeout(this.idleTimer); },
  bumpIdle(){
    clearTimeout(this.idleTimer);
    this.idleTimer=setTimeout(()=>{ if(Session.key){ Session.lock(); Router.go('unlock'); toast('Locked for safety'); } }, 1000*60*5); // NF-5 auto-lock
  }
};

/* ----------------------------------------------------------------------
   4. CONTENT — grounded in the PUBLIC framework only.
   Signs/symptoms are commonly-published indicators (MSF "Break the Silence"
   public material, MOE public guidance). NOT the proprietary SSSG items.
   ---------------------------------------------------------------------- */
const PROVENANCE = "Structured around Singapore’s public child-protection framework (MSF · SSSG/CARG pathway)";

const AGE_BANDS = [
  { id:'0-6',  label:'0–6 years',  hint:true,  sub:'Pre-verbal or limited speech' },
  { id:'7-12', label:'7–12 years', hint:false, sub:'Primary-school age' },
  { id:'13-17',label:'13–17 years',hint:false, sub:'Teenager' },
  { id:'unsure',label:'Not sure',  hint:false, sub:'', neutral:true }
];

/* Observable sign categories. Each sign carries a transparent weight used by
   the deterministic engine. Weights are a defensible heuristic that surfaces
   *concern level*, NOT a diagnosis — and are shown to the user as reasoning. */
const SIGNS = {
  physical: {
    title:'Physical signs', icon:'body',
    items:[
      { id:'p_unexplained', t:'Injuries that don’t match the explanation', w:3 },
      { id:'p_patterned',   t:'Marks in a pattern, or in unusual places', w:3 },
      { id:'p_repeated',    t:'Repeated injuries over time', w:3 },
      { id:'p_untreated',   t:'Untreated or poorly explained injuries', w:2 },
      { id:'p_hygiene',     t:'Persistent neglect of basic needs (hunger, hygiene, clothing)', w:2 },
    ]
  },
  behaviour: {
    title:'Behavioural signs', icon:'mind',
    items:[
      { id:'b_withdrawn', t:'Sudden withdrawal, fearfulness, or unusual quietness', w:2 },
      { id:'b_regress',   t:'Going back to younger behaviours (e.g. bedwetting, clinging)', w:2 },
      { id:'b_fear_adult',t:'Visible fear of a specific adult', w:3 },
      { id:'b_aggress',   t:'New aggression, or harming themselves', w:2 },
      { id:'b_avoid_home',t:'Reluctance to go home, or to be alone with someone', w:3 },
    ]
  },
  verbal: {
    title:'What they’ve said', icon:'speech',
    items:[
      { id:'v_disclosed', t:'They told me, directly or indirectly, that someone hurt them', w:4 },
      { id:'v_age_inappropriate', t:'Knowledge or talk beyond what fits their age', w:3 },
      { id:'v_inconsistent', t:'A story that keeps changing, or doesn’t add up', w:1 },
    ]
  }
};

/* Context modifiers — frequency & corroboration nudge the level, transparently. */
const FREQUENCY = [
  { id:'once',   label:'A one-off thing I noticed', w:0 },
  { id:'fewtimes',label:'A few times now', w:1 },
  { id:'pattern',label:'An ongoing pattern', w:2 },
  { id:'unsure', label:'Not sure', w:0, neutral:true },
];

/* ----------------------------------------------------------------------
   5. DETERMINISTIC RULES ENGINE  (AI-1, F-11, NF-10)
   Transparent, reproducible, explainable. Returns level + plain reasons.
   Hard rule: a direct disclosure (v_disclosed) or a clear danger flag
   always lifts to at least HIGH. A "Low" result is worded to preserve
   the option to escalate (spec §12.3).
   ---------------------------------------------------------------------- */
function assess(state){
  let score = 0;
  const reasons = [];
  const picked = state.signs || [];

  // sum sign weights, collect human-readable reasons
  for(const cat of Object.values(SIGNS)){
    for(const it of cat.items){
      if(picked.includes(it.id)){ score += it.w; reasons.push(it.t.toLowerCase()); }
    }
  }
  // frequency modifier
  const freq = FREQUENCY.find(f=>f.id===state.frequency);
  if(freq){ score += freq.w; if(freq.w>0) reasons.push(state.frequency==='pattern'?'it has been an ongoing pattern':'you’ve noticed it more than once'); }

  // 0–6 ambiguity caution: does NOT change the score up or down, but is flagged
  const youngFlag = state.ageBand==='0-6';

  // hard danger flags -> at least HIGH
  const disclosure = picked.includes('v_disclosed');
  const fearPattern = picked.includes('b_fear_adult') && picked.includes('b_avoid_home');

  let level;
  if(disclosure || fearPattern || score >= 8) level='high';
  else if(score >= 4) level='moderate';
  else level='low';

  return { level, score, reasons, youngFlag, disclosure };
}

/* Recommendation content keyed by role + level. Always a HUMAN escalation,
   never "we will report", never "confront the suspected person". (F-12) */
const SAY = [
  'Stay calm and let them lead — listen more than you ask',
  'Use open, gentle prompts: “Do you want to tell me about that?”',
  'Tell them you believe them and it’s not their fault',
  'Write down what you saw and heard, in their words, as soon as you can',
];
const AVOID = [
  'Don’t promise to keep it a secret',
  'Don’t ask leading questions or suggest what happened',
  'Don’t interrogate, repeat questions, or react with alarm',
  'Don’t confront the person you’re worried about',
];

/* Role-specific "who to talk to" — aligned to the public SSSG/CARG pathway. */
const ROUTES = {
  teacher:   { who:'your school counsellor or a CARG-trained colleague', extra:'They use the Child Abuse Reporting Guide (CARG) to decide on next steps.' },
  preschool: { who:'your centre’s designated child-protection lead', extra:'They can consult the CARG-trained pathway and ECDA guidance.' },
  nurse:     { who:'the medical social worker (MSW) at your facility', extra:'They can take the clinical concern into the reporting pathway.' },
  volunteer: { who:'your supervising staff member or programme lead', extra:'They can escalate to a CARG-trained professional.' },
  other:     { who:'a trained colleague, supervisor, or counsellor', extra:'They can take this into the official CARG pathway.' },
};
const ROLES = [
  { id:'teacher',   label:'Teacher' },
  { id:'preschool', label:'Preschool / early-years educator' },
  { id:'nurse',     label:'Healthcare worker' },
  { id:'volunteer', label:'Volunteer' },
  { id:'other',     label:'Something else' },
];

/* ----------------------------------------------------------------------
   6. ICONS (inline SVG, currentColor)
   ---------------------------------------------------------------------- */
const I = {
  ast:'<span class="ast">✻</span>',
  check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  back:'<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>',
  exit:'<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  lock:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  phone:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z"/></svg>',
  msg:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
  heart:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8z"/></svg>',
  x:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  book:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>',
  trash:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>',
  info:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
};

/* ----------------------------------------------------------------------
   7. UI HELPERS
   ---------------------------------------------------------------------- */
const $app = document.getElementById('app');
function h(html){ $app.innerHTML = html; window.scrollTo(0,0); $app.querySelector('.scroll')?.scrollTo(0,0); }
function toast(msg){ const t=document.getElementById('toast'); t.textContent=msg; t.classList.add('show'); clearTimeout(t._t); t._t=setTimeout(()=>t.classList.remove('show'),2200); }
function esc(s){ return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// quick-exit decoy (F-4 / R12)
function showDecoy(){ document.getElementById('decoy').classList.add('show'); }
function hideDecoy(){ document.getElementById('decoy').classList.remove('show'); }

function topbar(opts={}){
  const back = opts.back ? `<button class="back" onclick="${opts.back}">${I.back} Back</button>`
                         : `<span class="brandmark">${I.ast} Aster</span>`;
  return `<div class="topbar">
    ${back}
    <button class="exit" onclick="showDecoy()" aria-label="Quick exit">${I.exit} Leave</button>
  </div>`;
}

// transient working state for an in-progress assessment
let work = {};

/* ----------------------------------------------------------------------
   8. ROUTER
   ---------------------------------------------------------------------- */
const Router = {
  go(name, ...args){
    Session.bumpIdle();
    (Screens[name]||Screens.welcome)(...args);
  }
};
document.addEventListener('pointerdown',()=>{ if(Session.key) Session.bumpIdle(); });


/* ----------------------------------------------------------------------
   9. SCREENS
   ---------------------------------------------------------------------- */
const Screens = {};

/* --- 9.1 Welcome (first-ever run) --- */
Screens.welcome = function(){
  h(`<div class="screen">
    ${topbar()}
    <div class="scroll fadein" style="display:flex;flex-direction:column;padding-top:14px">
      <div style="font-size:46px;text-align:center;margin:24px 0 8px;color:var(--clay)">✻</div>
      <h1 class="center">Aster</h1>
      <p class="center lead muted" style="margin-top:10px">A quiet companion for the moment you notice something, and aren’t sure what to do next.</p>

      <div class="card" style="margin-top:24px">
        <p style="margin-bottom:14px"><b>What Aster is</b></p>
        <p class="muted" style="margin-bottom:8px">A short, private set of questions that helps you think clearly when you’re worried about a child — and points you to the right person to talk to.</p>
        <div class="divider" style="margin:16px 0"></div>
        <p style="margin-bottom:14px"><b>What Aster is not</b></p>
        <p class="muted tiny" style="margin:0">It doesn’t decide whether abuse happened. It doesn’t report anything for you. It never replaces a trained colleague — it helps you reach one.</p>
      </div>

      <div class="note" style="margin-top:14px">${I.lock} &nbsp;Everything you enter is locked on your device with a key only you hold. We can’t read it. There’s no name, email, or login required.</div>

      <div class="spacer"></div>
      <div class="foot-actions">
        <button class="btn btn-primary" onclick="Router.go('register')">Set up Aster</button>
        <button class="btn btn-quiet" onclick="Router.go('passphrase')">I already have a passphrase</button>
      </div>
    </div>
  </div>`);
};

/* --- 9.2 Registration (F-1, F-1a) --- */
Screens.register = function(){
  h(`<div class="screen">
    ${topbar({back:"Router.go('welcome')"})}
    <div class="scroll fadein">
      <div class="eyebrow">Set up — step 1 of 2</div>
      <h2>Choose a passphrase</h2>
      <p class="muted" style="margin-top:8px">Pick a username only you’d recognise (it can be anything — not your real name) and a passphrase. Your passphrase becomes the key that locks your data. <b>We never see it.</b></p>

      <div class="field" style="margin-top:18px">
        <label>Username</label>
        <input class="input" id="r_user" autocomplete="off" autocapitalize="off" placeholder="e.g. quietfern" />
      </div>
      <div class="field">
        <label>Passphrase</label>
        <input class="input" id="r_pass" type="password" autocomplete="new-password" placeholder="A phrase you’ll remember" />
      </div>
      <div class="field">
        <label>Repeat passphrase</label>
        <input class="input" id="r_pass2" type="password" autocomplete="new-password" placeholder="Type it again" />
      </div>

      <div class="note warm tiny">Because only you hold the key, <b>we can’t reset it.</b> If you forget your passphrase, you’ll need the recovery code we show you next.</div>

      <div class="foot-actions">
        <button class="btn btn-primary" id="r_go" onclick="doRegister()">Continue</button>
      </div>
    </div>
  </div>`);
  setTimeout(()=>document.getElementById('r_user')?.focus(),200);
};

async function doRegister(){
  const user=document.getElementById('r_user').value.trim();
  const p1=document.getElementById('r_pass').value;
  const p2=document.getElementById('r_pass2').value;
  if(user.length<3) return toast('Pick a username (3+ characters)');
  if(p1.length<8)  return toast('Use a passphrase of 8+ characters');
  if(p1!==p2)      return toast('Passphrases don’t match');
  if(Server.getAccount(user)) return toast('That username is taken — try another');

  const btn=document.getElementById('r_go'); btn.textContent='Securing…';
  const salt=Crypto.randSalt();
  const key=await Crypto.deriveKey(p1, salt);

  // verification artifact: encrypt a known token so unlock can check the key
  const verify=await Crypto.encrypt(key, {v:'aster-ok'});
  // recovery: a second key derived from the recovery code, wrapping the salt
  const code=Crypto.recoveryCode();
  const recSalt=Crypto.randSalt();
  const recKey=await Crypto.deriveKey(code, recSalt);
  const recWrap=await Crypto.encrypt(recKey, {p:p1}); // recovery restores access to passphrase

  Server.putAccount(user, {
    salt:Crypto.b64(salt), verify,
    recSalt:Crypto.b64(recSalt), recWrap,
    blob: await Crypto.encrypt(key, [])   // empty journal
  });

  Session.handle=user; Session.key=key; Session._pass=p1; Session.journal=[]; Session.profile={role:null};
  Screens.recovery(code);
}

/* --- 9.3 Recovery code (F-1b) — must be acknowledged --- */
Screens.recovery = function(code){
  h(`<div class="screen">
    ${topbar()}
    <div class="scroll fadein">
      <div class="eyebrow">Set up — step 2 of 2</div>
      <h2>Save your recovery code</h2>
      <p class="muted" style="margin-top:8px">This is the <b>only</b> way back in if you forget your passphrase. Write it down or store it somewhere safe — a password manager, a note you trust. We don’t keep a copy.</p>

      <div class="recovery" style="margin:20px 0">${code}</div>
      <button class="btn btn-ghost" onclick="copyCode('${code}')">Copy code</button>

      <div class="note warm" style="margin-top:18px">If you lose both your passphrase <b>and</b> this code, your saved notes can’t be recovered — by anyone. That’s the trade-off that keeps them truly private.</div>

      <label class="choice" id="ack_row" onclick="toggleAck()" style="margin-top:20px">
        <span class="tick" id="ack_tick">${I.check}</span>
        <span>I’ve saved my recovery code somewhere safe.</span>
      </label>

      <div class="foot-actions">
        <button class="btn btn-primary" id="ack_btn" disabled style="opacity:.5" onclick="finishSetup()">Enter Aster</button>
      </div>
    </div>
  </div>`);
};
let _ack=false;
function toggleAck(){ _ack=!_ack; document.getElementById('ack_row').classList.toggle('sel',_ack);
  const b=document.getElementById('ack_btn'); b.disabled=!_ack; b.style.opacity=_ack?'1':'.5'; }
function copyCode(c){ navigator.clipboard?.writeText(c).then(()=>toast('Copied'),()=>toast('Copy it manually')); }
function finishSetup(){ if(!_ack)return; _ack=false; Router.go('setrole'); }

/* --- Role, asked ONCE at setup (stored encrypted in the account profile) ---
   Role is a stable property of the user, not of each case, so we capture it
   here and never ask again. It can be changed later in Settings. */
Screens.setrole = function(){
  const rows=ROLES.map(r=>`<button class="choice ${Session.profile.role===r.id?'sel':''}" onclick="pickSetupRole('${r.id}')">
    <span class="tick">${I.check}</span><span>${r.label}</span></button>`).join('');
  h(`<div class="screen">
    ${topbar()}
    <div class="scroll fadein">
      <div class="eyebrow">One last thing</div>
      <h2>What’s your role?</h2>
      <p class="muted" style="margin-top:8px">So Aster can point you to the right person to talk to. You’ll only be asked this once — you can change it anytime in Settings.</p>
      <div style="margin-top:18px">${rows}</div>
    </div>
  </div>`);
};
async function pickSetupRole(id){
  Session.profile.role=id;
  await persistProfile();
  offerTrustDevice();
}

/* offer fast re-unlock PIN on this device (F-2) */
function offerTrustDevice(){
  h(`<div class="screen">
    ${topbar()}
    <div class="scroll fadein">
      <h2>Faster unlock on this device?</h2>
      <p class="muted" style="margin-top:8px">You can set a short PIN to reopen Aster quickly here, so you don’t retype your passphrase each time. On a new device, your passphrase is still required.</p>
      <div class="note">${I.shield} &nbsp;The PIN only works on this device. It unlocks the key that’s already stored here — it’s never sent anywhere.</div>
      <div class="foot-actions">
        <button class="btn btn-primary" onclick="Router.go('setpin')">Set a quick PIN</button>
        <button class="btn btn-quiet" onclick="Router.go('home')">Skip — I’ll use my passphrase</button>
      </div>
    </div>
  </div>`);
}


/* --- 9.4 Set PIN (fast re-unlock; wraps the passphrase locally) ---
   Real fast re-unlock: wrap the user's passphrase under a PIN-derived key,
   stored ON THIS DEVICE ONLY. A correct PIN unwraps it and unlocks the data
   with no passphrase retype. A new device has no trusted record, so the
   passphrase is still required there. (F-2) */
let _pinBuf='';
Screens.setpin = function(){
  _pinBuf='';
  if(!Session._pass){ toast('Use your passphrase first to enable a PIN'); return Router.go('home'); }
  renderPin('Choose a 4-digit PIN','setpin', async (pin)=>{
    const pinSalt=Crypto.randSalt();
    const pinKey=await Crypto.deriveKey('PIN:'+pin, pinSalt);
    const wrap=await Crypto.encrypt(pinKey, { p:Session._pass });   // only a correct PIN unwraps the passphrase
    Session.setTrusted({ handle:Session.handle, pinSalt:Crypto.b64(pinSalt), wrap });
    toast('Quick unlock ready');
    Router.go('home');
  });
};

function renderPin(title, mode, onComplete, footer){
  const dots=[0,1,2,3].map(i=>`<div class="pindot ${i<_pinBuf.length?'on':''}"></div>`).join('');
  const keys=[1,2,3,4,5,6,7,8,9].map(n=>`<button class="key" onclick="pinPush('${n}','${mode}',${onComplete?'true':'false'})">${n}</button>`).join('');
  h(`<div class="screen">
    ${topbar({back: mode==='setpin' ? "Router.go('home')" : "Router.go('welcome')"})}
    <div class="scroll center fadein" style="display:flex;flex-direction:column;justify-content:center">
      <div style="font-size:34px;color:var(--clay)">✻</div>
      <h2 style="margin-top:10px">${title}</h2>
      <div class="pinrow">${dots}</div>
      <div class="keypad">
        ${keys}
        <button class="key fn" onclick="pinClear()">Clear</button>
        <button class="key" onclick="pinPush('0','${mode}',${onComplete?'true':'false'})">0</button>
        <button class="key fn" onclick="pinBack()">⌫</button>
      </div>
      ${footer||''}
    </div>
  </div>`);
  Screens._pinComplete = onComplete;
}
function pinPush(n, mode){
  if(_pinBuf.length>=4) return;
  _pinBuf+=n;
  document.querySelectorAll('.pindot')[_pinBuf.length-1]?.classList.add('on');
  if(_pinBuf.length===4){ const cb=Screens._pinComplete; const v=_pinBuf; setTimeout(()=>cb&&cb(v),180); }
}
function pinBack(){ _pinBuf=_pinBuf.slice(0,-1); document.querySelectorAll('.pindot').forEach((d,i)=>d.classList.toggle('on',i<_pinBuf.length)); }
function pinClear(){ _pinBuf=''; document.querySelectorAll('.pindot').forEach(d=>d.classList.remove('on')); }

/* --- 9.5 Unlock (F-3) — passphrase, or fast PIN if device trusted --- */
Screens.unlock = function(){
  const trusted=Session.trusted();
  if(trusted && trusted.wrap){
    _pinBuf='';
    const escape=`<button class="btn btn-quiet" style="margin-top:22px" onclick="Router.go('passphrase','${esc(trusted.handle)}')">Forgot your PIN? Use your passphrase</button>`;
    renderPin('Enter your PIN','unlockpin', async (pin)=>{
      try{
        const pinKey=await Crypto.deriveKey('PIN:'+pin, Crypto.unb64(trusted.pinSalt));
        const { p }=await Crypto.decrypt(pinKey, trusted.wrap);   // unwrap passphrase (throws if PIN wrong)
        const acc=Server.getAccount(trusted.handle);
        const key=await Crypto.deriveKey(p, Crypto.unb64(acc.salt));
        await Crypto.decrypt(key, acc.verify);                    // verify gate
        Session.handle=trusted.handle; Session.key=key; Session._pass=p;
        Session.journal=await Crypto.decrypt(key, acc.blob);
        Session.profile=await loadProfile(key, acc);
        Router.go('home');
      }catch(e){ pinClear(); toast('That PIN didn’t match'); }
    }, escape);
  } else {
    Router.go('passphrase');
  }
};

/* passphrase entry (used for new device / after sign out / behind PIN) */
Screens.passphrase = function(prefillHandle){
  h(`<div class="screen">
    ${topbar({back:"Router.go('welcome')"})}
    <div class="scroll fadein" style="display:flex;flex-direction:column">
      <div style="font-size:34px;text-align:center;color:var(--clay);margin-top:18px">✻</div>
      <h2 class="center" style="margin-top:8px">Welcome back</h2>
      <p class="center muted" style="margin-top:6px">Unlock with your passphrase.</p>

      <div class="field" style="margin-top:22px">
        <label>Username</label>
        <input class="input" id="u_user" autocomplete="off" autocapitalize="off" value="${esc(prefillHandle||'')}" placeholder="Your username" />
      </div>
      <div class="field">
        <label>Passphrase</label>
        <input class="input" id="u_pass" type="password" autocomplete="current-password" placeholder="Your passphrase" />
      </div>

      <button class="btn btn-primary" id="u_go" onclick="doUnlock()">Unlock</button>
      <button class="btn btn-quiet" onclick="Router.go('recover')">I’ve forgotten my passphrase</button>
    </div>
  </div>`);
  setTimeout(()=>document.getElementById(prefillHandle?'u_pass':'u_user')?.focus(),200);
};

async function doUnlock(){
  const user=document.getElementById('u_user').value.trim();
  const pass=document.getElementById('u_pass').value;
  const acc=Server.getAccount(user);
  if(!acc) return toast('No account with that username here');
  const btn=document.getElementById('u_go'); btn.textContent='Unlocking…';
  try{
    const key=await Crypto.deriveKey(pass, Crypto.unb64(acc.salt));
    await Crypto.decrypt(key, acc.verify);             // verify gate
    Session.handle=user; Session.key=key; Session._pass=pass;
    Session.journal=await Crypto.decrypt(key, acc.blob);  // F-3a restore-on-login
    Session.profile=await loadProfile(key, acc);
    Router.go('home');
  }catch(e){ btn.textContent='Unlock'; toast('That didn’t unlock — check your passphrase'); }
}

/* --- 9.6 Recover with code (F-1b) --- */
Screens.recover = function(){
  h(`<div class="screen">
    ${topbar({back:"Router.go('passphrase')"})}
    <div class="scroll fadein">
      <h2>Use your recovery code</h2>
      <p class="muted" style="margin-top:8px">Enter your username and the recovery code you saved at setup. You’ll then set a new passphrase.</p>
      <div class="field" style="margin-top:18px">
        <label>Username</label>
        <input class="input" id="rc_user" autocomplete="off" autocapitalize="off" />
      </div>
      <div class="field">
        <label>Recovery code</label>
        <input class="input" id="rc_code" autocapitalize="characters" placeholder="XXXX-XXXX-XXXX" />
      </div>
      <button class="btn btn-primary" id="rc_go" onclick="doRecover()">Recover access</button>
      <div class="note warm tiny" style="margin-top:14px">No code? Then this data can’t be recovered — that’s the privacy trade-off. You can start fresh from the welcome screen; your saved notes were optional.</div>
    </div>
  </div>`);
};
async function doRecover(){
  const user=document.getElementById('rc_user').value.trim();
  const code=document.getElementById('rc_code').value.trim().toUpperCase();
  const acc=Server.getAccount(user);
  if(!acc) return toast('No account with that username');
  const btn=document.getElementById('rc_go'); btn.textContent='Checking…';
  try{
    const recKey=await Crypto.deriveKey(code, Crypto.unb64(acc.recSalt));
    const {p}=await Crypto.decrypt(recKey, acc.recWrap);
    // recovered the old passphrase — unlock, then prompt to set a new one
    const key=await Crypto.deriveKey(p, Crypto.unb64(acc.salt));
    Session.handle=user; Session.key=key; Session._pass=p;
    Session.journal=await Crypto.decrypt(key, acc.blob);
    Session.profile=await loadProfile(key, acc);
    toast('Recovered — please set a new passphrase');
    Router.go('home');
  }catch(e){ btn.textContent='Recover access'; toast('That code didn’t match'); }
}


/* --- 9.7 Home --- */
Screens.home = function(){
  const n=Session.journal.length;
  const roleLabel=(ROLES.find(r=>r.id===Session.profile.role)||{}).label;
  const roleChip = roleLabel
    ? `<button class="rolechip" onclick="Router.go('changerole')" aria-label="Your role, tap to change">
         <span class="dotmark"></span><span>${roleLabel}</span>
         <span class="chg">Change</span>
       </button>`
    : `<button class="rolechip" onclick="Router.go('changerole')">
         <span class="dotmark"></span><span class="muted">Set your role</span>
         <span class="chg">Set</span>
       </button>`;
  h(`<div class="screen">
    ${topbar()}
    <div class="scroll fadein" style="display:flex;flex-direction:column;padding-top:12px">
      <h1 style="margin-top:18px">Hello.</h1>
      <p class="lead muted" style="margin-top:8px">When you’re ready, take it one quiet question at a time.</p>

      ${roleChip}

      <button class="card" style="text-align:left;margin-top:18px;border-color:var(--sage);background:linear-gradient(135deg,var(--sage),var(--sage-deep));color:#fff;box-shadow:var(--shadow-lg)" onclick="startFlow()">
        <div style="font-size:13px;opacity:.85;letter-spacing:.06em;text-transform:uppercase;font-weight:600">Start here</div>
        <div style="font-family:var(--serif);font-size:24px;margin-top:6px">I’m worried about a child</div>
        <div style="opacity:.9;font-size:14.5px;margin-top:6px">A short walk-through to help you think it through and find the right next step. About 2 minutes.</div>
      </button>

      <button class="card" style="text-align:left;display:flex;align-items:center;gap:14px" onclick="Router.go('journal')">
        <span style="flex:none;width:44px;height:44px;border-radius:12px;background:var(--clay-soft);color:var(--clay);display:flex;align-items:center;justify-content:center">${I.book}</span>
        <span><b>Past entries</b><br><span class="muted tiny">${n? `${n} saved · only you can open them` : 'Nothing saved yet'}</span></span>
      </button>

      <button class="card" style="text-align:left;display:flex;align-items:center;gap:14px" onclick="Router.go('sources')">
        <span style="flex:none;width:44px;height:44px;border-radius:12px;background:var(--sky-soft);color:var(--sky);display:flex;align-items:center;justify-content:center">${I.info}</span>
        <span><b>How Aster works &amp; sources</b><br><span class="muted tiny">What it’s based on, and what it won’t do</span></span>
      </button>

      <button class="card" style="text-align:left;display:flex;align-items:center;gap:14px" onclick="Router.go('care')">
        <span style="flex:none;width:44px;height:44px;border-radius:12px;background:var(--clay-soft);color:var(--clay);display:flex;align-items:center;justify-content:center">${I.heart}</span>
        <span><b>A moment for you</b><br><span class="muted tiny">A pause to look after yourself</span></span>
      </button>

      <div class="spacer"></div>
      <div class="foot-actions">
        <div class="emerg" style="margin:0">
          <h3>If a child is in immediate danger</h3>
          <p class="tiny" style="margin:0 0 12px;color:#7a4030">Don’t wait for this app. Call the police now.</p>
          <div class="btn-row">
            <a class="btn btn-emergency" href="tel:${EMERGENCY.police_call}">${I.phone} Call ${EMERGENCY.police_call}</a>
            <a class="btn btn-ghost" href="sms:${EMERGENCY.police_sms}">${I.msg} SMS ${EMERGENCY.police_sms}</a>
          </div>
        </div>
        <button class="btn btn-quiet" onclick="Router.go('settings')" style="margin-top:8px">Settings &amp; sign out</button>
      </div>
    </div>
  </div>`);
};

/* --- Change role (reached from the home chip) --- */
Screens.changerole = function(){
  const rows=ROLES.map(r=>`<button class="choice ${Session.profile.role===r.id?'sel':''}" onclick="setRoleFromHome('${r.id}')">
    <span class="tick">${I.check}</span><span>${r.label}</span></button>`).join('');
  h(`<div class="screen">
    ${topbar({back:"Router.go('home')"})}
    <div class="scroll fadein">
      <h2>Your role</h2>
      <p class="muted" style="margin-top:8px">Aster uses this to point you to the right person to talk to. Change it whenever your role changes.</p>
      <div style="margin-top:18px">${rows}</div>
    </div>
  </div>`);
};
async function setRoleFromHome(id){
  Session.profile.role=id;
  await persistProfile();
  toast('Role updated');
  Router.go('home');
}

/* ----------------------------------------------------------------------
   10. THE GUIDED FLOW (F-6..F-10) — branching, one question per screen,
   "Not sure"/"Skip" first-class, < ~2 min, back-navigable.
   ---------------------------------------------------------------------- */
function startFlow(){ work={ step:0, ageBand:null, signs:[], frequency:null }; flowStep(); }

const FLOW = ['age','signs_physical','signs_behaviour','signs_verbal','frequency','present'];

function flowStep(){
  const s=FLOW[work.step];
  const pct=Math.round((work.step/(FLOW.length))*100);
  ({
    age:q_age,
    signs_physical:()=>q_signs('physical'),
    signs_behaviour:()=>q_signs('behaviour'),
    signs_verbal:()=>q_signs('verbal'),
    frequency:q_frequency, present:q_present
  })[s](pct);
}
function flowNext(){ if(work.step<FLOW.length-1){ work.step++; flowStep(); } else { computeResult(); } }
function flowBack(){ if(work.step>0){ work.step--; flowStep(); } else { Router.go('home'); } }

function flowShell(pct, inner, opts={}){
  h(`<div class="screen">
    ${topbar({back:'flowBack()'})}
    <div class="scroll fadein">
      <div class="prog"><i style="width:${pct}%"></i></div>
      ${inner}
    </div>
    <div class="foot-actions" style="padding-left:22px;padding-right:22px">
      ${opts.footer||''}
    </div>
  </div>`);
}

/* age band — flags 0–6 caution (F-8) */
function q_age(pct){
  const rows=AGE_BANDS.map(a=>`<button class="choice ${a.neutral?'neutral':''} ${work.ageBand===a.id?'sel':''}" onclick="work.ageBand='${a.id}';flowNext()">
    <span class="tick">${I.check}</span>
    <span>${a.label}${a.sub?`<br><span class="muted tiny">${a.sub}</span>`:''}</span></button>`).join('');
  flowShell(pct, `<h2>Roughly how old is the child?</h2>
    <p class="muted" style="margin-top:8px">A rough band is fine.</p>
    <div style="margin-top:18px">${rows}</div>`);
}

/* signs — multi-select per category, with Not sure / None (F-7) */
function q_signs(cat){
  const pct=Math.round((work.step/FLOW.length)*100);
  const C=SIGNS[cat];
  const rows=C.items.map(it=>{
    const sel=work.signs.includes(it.id);
    return `<button class="choice ${sel?'sel':''}" id="sign_${it.id}" onclick="toggleSign('${it.id}',this)">
      <span class="tick">${I.check}</span><span>${it.t}</span></button>`;
  }).join('');
  flowShell(pct, `<h2>${C.title}</h2>
    <p class="muted" style="margin-top:8px">Tick anything you’ve noticed. It’s fine to tick none — uncertainty is normal here.</p>
    <div style="margin-top:18px">${rows}
      <button class="choice neutral ${work['none_'+cat]?'sel':''}" id="none_${cat}" onclick="markNone('${cat}',this)">
        <span class="tick">${I.check}</span><span>Nothing here / not sure</span></button>
    </div>`,
    { footer:`<button class="btn btn-primary" onclick="flowNext()">Continue</button>` });
}
/* In-place toggle — no full re-render, so the UI never flickers. */
function toggleSign(id, el){
  const i=work.signs.indexOf(id);
  if(i>=0) work.signs.splice(i,1); else work.signs.push(id);
  el.classList.toggle('sel', i<0);                 // reflect new state on this button only
  const cat=FLOW[work.step].replace('signs_','');
  work['none_'+cat]=false;
  document.getElementById('none_'+cat)?.classList.remove('sel');  // picking a sign clears "none"
}
function markNone(cat, el){
  // clear this category's signs (state + their buttons), select "none"
  SIGNS[cat].items.forEach(it=>{
    const j=work.signs.indexOf(it.id); if(j>=0) work.signs.splice(j,1);
    document.getElementById('sign_'+it.id)?.classList.remove('sel');
  });
  work['none_'+cat]=true;
  el.classList.add('sel');
}

/* frequency (F-6 context) */
function q_frequency(pct){
  const rows=FREQUENCY.map(f=>`<button class="choice ${f.neutral?'neutral':''} ${work.frequency===f.id?'sel':''}" onclick="work.frequency='${f.id}';flowNext()">
    <span class="tick">${I.check}</span><span>${f.label}</span></button>`).join('');
  flowShell(pct, `<h2>How often have you seen this?</h2>
    <p class="muted" style="margin-top:8px">Patterns matter more than any single moment.</p>
    <div style="margin-top:18px">${rows}</div>`);
}

/* "is the person of concern present right now?" — the safety branch (F-5/R5) */
function q_present(pct){
  flowShell(pct, `<h2>One last thing</h2>
    <p class="muted" style="margin-top:8px">Right now, is the person you’re worried about <b>with you</b>, or able to see your screen?</p>
    <div style="margin-top:18px">
      <button class="choice" onclick="work.present=true;computeResult()"><span class="tick">${I.check}</span><span>Yes — they’re here / nearby</span></button>
      <button class="choice" onclick="work.present=false;computeResult()"><span class="tick">${I.check}</span><span>No — I have a private moment</span></button>
      <button class="choice neutral" onclick="work.present=null;computeResult()"><span class="tick">${I.check}</span><span>Not sure</span></button>
    </div>`);
}


/* ----------------------------------------------------------------------
   11. RESULT (F-11..F-15)  — risk + reasons + say/avoid + escalation
   + emergency override + good-faith reassurance. Never a verdict.
   ---------------------------------------------------------------------- */
function computeResult(){
  const r=assess(work);
  work.result=r;
  Session.didAssess=true;   // used to decide whether sign-out shows the care pause
  Screens.result(r);
}

const LEVEL_COPY = {
  low:{ title:'Worth keeping an eye on', sub:'What you’ve described doesn’t point strongly to harm right now — but noticing was the right thing to do.' },
  moderate:{ title:'Worth raising with someone', sub:'Several things you’ve noticed are the kind the guidelines take seriously. This is a reasonable concern to talk through.' },
  high:{ title:'Please talk to someone soon', sub:'What you’ve described includes signs the guidelines treat as serious. A trained colleague should hear about this.' }
};

Screens.result = function(r){
  const route=ROUTES[Session.profile.role]||ROUTES.other;
  const copy=LEVEL_COPY[r.level];

  // present-person safety branch (R5) — show first if relevant
  const presentBlock = (work.present===true) ? `
    <div class="note warm" style="margin-top:14px">
      <b>Because they’re nearby:</b> this isn’t the moment to ask the child questions or act on the concern. Wait until you have a private, calm moment. If you feel the child is in immediate danger, use the emergency step below.
    </div>` : '';

  // young-child caution (F-8)
  const youngBlock = r.youngFlag ? `
    <div class="note" style="margin-top:14px">
      <b>A note on very young children:</b> under-6s often can’t explain what’s happening, and can give mixed signals — a hurt child may still play and laugh. That doesn’t mean nothing is wrong, and it doesn’t mean something is. Aster can’t tell you whether an injury is or isn’t abuse — only a trained person can weigh that. Trust that noticing was right.
    </div>` : '';

  const reasonText = r.reasons.length
    ? `You noted ${humanList(r.reasons.slice(0,4))}${r.reasons.length>4?', and more':''}.`
    : `You didn’t tick specific signs — which is completely valid. A quiet sense that something’s off is itself worth holding onto.`;

  const sayRows=SAY.map(s=>`<div class="sa say"><span class="ic">${I.check}</span><span>${s}</span></div>`).join('');
  const avoidRows=AVOID.map(s=>`<div class="sa avoid"><span class="ic">${I.x}</span><span>${s}</span></div>`).join('');

  h(`<div class="screen">
    ${topbar({back:"Router.go('home')"})}
    <div class="scroll fadein" style="padding-top:6px">
      <div class="band ${r.level}">
        <div class="lvl">${copy.title}</div>
        <div class="sub">${copy.sub}</div>
      </div>

      ${presentBlock}
      ${youngBlock}

      <div class="card" style="margin-top:14px">
        <div class="prov">${I.shield} ${PROVENANCE}</div>
        <p style="margin:14px 0 0"><b>Why you’re seeing this</b></p>
        <p class="muted" style="margin:6px 0 0">${reasonText} This is decision <i>support</i> — not a clinical or legal judgement. The decision is always yours and your trained colleague’s.</p>
      </div>

      <div class="card">
        <p style="margin:0 0 6px"><b>Your next step</b></p>
        <p class="muted" style="margin:0 0 4px">Bring this to ${route.who}.</p>
        <p class="tiny muted" style="margin:0">${route.extra}</p>
      </div>

      <div class="card">
        <p style="margin:0 0 10px"><b>If you speak with the child</b></p>
        ${sayRows}
        <div style="height:10px"></div>
        ${avoidRows}
      </div>

      <div class="card">
        <p style="margin:0 0 8px"><b>You’re protected when you raise a concern</b></p>
        <p class="muted tiny" style="margin:0">In Singapore, reporting in good faith carries no civil or criminal liability, and what you share is kept confidential. You don’t need to be certain — you only need a reasonable concern.</p>
      </div>

      <div class="emerg">
        <h3>If the child’s life is in danger</h3>
        <p class="tiny" style="margin:0 0 12px;color:#7a4030">This is the official instruction, not Aster’s decision: call the police immediately.</p>
        <div class="btn-row">
          <a class="btn btn-emergency" href="tel:${EMERGENCY.police_call}">${I.phone} ${EMERGENCY.police_call}</a>
          <a class="btn btn-ghost" href="sms:${EMERGENCY.police_sms}">${I.msg} ${EMERGENCY.police_sms}</a>
        </div>
        <p class="tiny" style="margin:12px 0 0;color:#7a4030">For the trained escalation route, the 24-hour helpline is <b>NAVH ${EMERGENCY.navh}</b>.</p>
        <a class="btn btn-ghost" href="tel:${EMERGENCY.navh_tel}" style="margin-top:10px">${I.phone} Call NAVH</a>
      </div>

      <div class="foot-actions">
        <button class="btn btn-primary" onclick="offerSave()">${I.book} Save this privately?</button>
        <button class="btn btn-quiet" onclick="Router.go('care')">A moment for you →</button>
      </div>
    </div>
  </div>`);
};

function humanList(arr){
  if(arr.length===1) return arr[0];
  return arr.slice(0,-1).join(', ')+' and '+arr[arr.length-1];
}

/* --- 11.1 Care for the noticer (NF-8 / Criterion 3) --- */
Screens.care = function(mode){
  const signout = mode==='signout';
  const intro = signout
    ? 'Before you go — a small pause. Carrying a worry about a child is its own quiet weight, and you’ve been holding some of it today.'
    : 'Carrying a worry about a child is its own quiet weight. Noticing, and choosing to act, takes something out of you. That’s worth acknowledging.';
  const action = signout
    ? `<button class="btn btn-primary" onclick="finishSignOut()">Sign out</button>
       <button class="btn btn-quiet" onclick="Router.go('home')">Stay for now</button>`
    : `<button class="btn btn-primary" onclick="Router.go('home')">Back to start</button>`;
  h(`<div class="screen">
    ${topbar({back: signout ? "Router.go('settings')" : "Router.go('home')"})}
    <div class="scroll fadein">
      <div style="font-size:34px;color:var(--clay);margin-top:14px">${I.heart}</div>
      <h2 style="margin-top:10px">This is heavy work.</h2>
      <p class="muted" style="margin-top:8px">${intro}</p>
      <div class="card">
        <p style="margin:0"><b>A few small things that help:</b></p>
        <p class="muted" style="margin:10px 0 0">Tell one trusted colleague or supervisor that this is sitting with you — you don’t have to carry it alone.</p>
        <p class="muted" style="margin:10px 0 0">If your workplace has a debrief or supervision structure, this is exactly what it’s for.</p>
        <p class="muted" style="margin:10px 0 0">You did the right thing by paying attention. The outcome isn’t yours alone to control.</p>
      </div>
      <div class="foot-actions">${action}</div>
    </div>
  </div>`);
};


/* ----------------------------------------------------------------------
   12. ENCRYPTED JOURNAL (F-16..F-19) — opt-in, no identity, deletable.
   Save re-encrypts the whole journal and pushes ciphertext to the "server".
   ---------------------------------------------------------------------- */
async function persistJournal(){
  const acc=Server.getAccount(Session.handle);
  acc.blob=await Crypto.encrypt(Session.key, Session.journal);
  Server.putAccount(Session.handle, acc);
}

/* Profile (role) is encrypted with the same key, stored separately from the
   journal so the journal logic stays untouched. (role asked once at setup) */
async function persistProfile(){
  const acc=Server.getAccount(Session.handle);
  acc.profileBlob=await Crypto.encrypt(Session.key, Session.profile);
  Server.putAccount(Session.handle, acc);
}
async function loadProfile(key, acc){
  if(acc && acc.profileBlob){
    try{ return await Crypto.decrypt(key, acc.profileBlob); }catch{ /* fall through */ }
  }
  return { role:null };
}

function offerSave(){
  h(`<div class="screen">
    ${topbar({back:"Screens.result(work.result)"})}
    <div class="scroll fadein">
      <h2>Save this to your private journal?</h2>
      <p class="muted" style="margin-top:8px">It’s entirely your choice — Aster never saves anything on its own. If you save it, it’s encrypted with your key and reachable only by you, on any device you sign in to.</p>

      <div class="field" style="margin-top:18px">
        <label>Give it a name only you’d recognise (optional)</label>
        <input class="input" id="ctx_label" maxlength="40" placeholder="e.g. ‘the quiet one in class 2B’ or ‘K’" value="${esc(work.label||'')}" />
      </div>
      <div class="note tiny">${I.lock} <b>Please don’t use anyone’s real name.</b> A made-up initial or nickname is perfect — and it’s only needed if you save. Nothing identifying is stored.</div>

      <div class="foot-actions">
        <button class="btn btn-primary" onclick="saveEntry()">Save it privately</button>
        <button class="btn btn-quiet" onclick="Router.go('home')">No, don’t save</button>
      </div>
    </div>
  </div>`);
  setTimeout(()=>document.getElementById('ctx_label')?.focus(),200);
}

async function saveEntry(){
  const labelEl=document.getElementById('ctx_label');
  const label=(labelEl?labelEl.value.trim():'') || 'Untitled note';
  const entry={
    id:'e'+Date.now(),
    when:Date.now(),
    label,
    role:Session.profile.role, ageBand:work.ageBand,
    level:work.result.level, reasons:work.result.reasons,
    signs:work.signs.slice(), frequency:work.frequency
  };
  Session.journal.unshift(entry);
  await persistJournal();
  toast('Saved — locked to your key');
  Router.go('home');
}

Screens.journal = function(){
  const list=Session.journal;
  const body = list.length ? list.map(e=>{
    const d=new Date(e.when);
    const dot=e.level==='high'?'#8a7d5e':e.level==='moderate'?'var(--clay)':'var(--sage)';
    return `<button class="entry" onclick="Router.go('entry','${e.id}')">
      <span class="dot" style="background:${dot}">${esc((e.label||'?')[0].toUpperCase())}</span>
      <span class="meta"><b>${esc(e.label)}</b><span class="rl ${e.level}" style="margin-left:8px">${e.level}</span><br>
        <span class="when">${d.toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'})} · ${d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})}</span></span>
    </button>`;
  }).join('') : `<div class="card center" style="padding:34px 20px"><div style="font-size:30px;color:var(--clay)">✻</div><p class="muted" style="margin:12px 0 0">Nothing saved yet.<br>Anything you save will appear here, locked to your key.</p></div>`;

  h(`<div class="screen">
    ${topbar({back:"Router.go('home')"})}
    <div class="scroll fadein">
      <h2>Past entries</h2>
      <p class="muted tiny" style="margin-top:6px">${I.lock} Encrypted with your key. Reachable on any device you sign in to — never readable by us.</p>
      <div style="margin-top:18px">${body}</div>
    </div>
  </div>`);
};

Screens.entry = function(id){
  const e=Session.journal.find(x=>x.id===id);
  if(!e) return Router.go('journal');
  const d=new Date(e.when);
  const reasons=e.reasons&&e.reasons.length? `You noted ${humanList(e.reasons.slice(0,4))}.` : 'No specific signs were ticked — a quiet sense that something was off.';
  const route=ROUTES[e.role]||ROUTES.other;
  h(`<div class="screen">
    ${topbar({back:"Router.go('journal')"})}
    <div class="scroll fadein">
      <div class="band ${e.level}"><div class="lvl">${esc(e.label)}</div><div class="sub">${LEVEL_COPY[e.level].title} · ${d.toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'})}</div></div>
      <div class="card" style="margin-top:14px">
        <p style="margin:0 0 6px"><b>What you noticed</b></p>
        <p class="muted" style="margin:0">${reasons}</p>
      </div>
      <div class="card"><p style="margin:0 0 4px"><b>Suggested next step at the time</b></p><p class="muted" style="margin:0">Bring this to ${route.who}.</p></div>
      <div class="foot-actions">
        <button class="btn btn-emergency" onclick="deleteEntry('${e.id}')">${I.trash} Delete this entry</button>
      </div>
    </div>
  </div>`);
};
async function deleteEntry(id){
  Session.journal=Session.journal.filter(x=>x.id!==id);
  await persistJournal();
  toast('Deleted'); Router.go('journal');
}

/* ----------------------------------------------------------------------
   13. SETTINGS — sign out (F-3b) and erase-all (F-19 true deletion)
   ---------------------------------------------------------------------- */
Screens.settings = function(){
  h(`<div class="screen">
    ${topbar({back:"Router.go('home')"})}
    <div class="scroll fadein">
      <h2>Settings</h2>
      <div class="card" style="margin-top:18px">
        <p style="margin:0 0 6px"><b>Your role</b></p>
        <p class="muted tiny" style="margin:0 0 12px">Aster uses this to point you to the right person. Change it if your role changes.</p>
        ${ROLES.map(r=>`<button class="choice ${Session.profile.role===r.id?'sel':''}" style="margin-bottom:9px" onclick="changeRole('${r.id}')">
          <span class="tick">${I.check}</span><span>${r.label}</span></button>`).join('')}
      </div>
      <div class="card">
        <p style="margin:0 0 6px"><b>Quick exit</b></p>
        <p class="muted tiny" style="margin:0 0 12px">The “Leave” button at the top of every screen instantly blanks Aster to a neutral page. Use it if someone glances over.</p>
        <button class="btn btn-ghost" onclick="showDecoy()">Try quick exit</button>
      </div>
      ${pinCard()}
      <div class="card">
        <p style="margin:0 0 6px"><b>Sign out of this device</b></p>
        <p class="muted tiny" style="margin:0 0 12px">Clears the key and any decrypted notes from this device. Your data stays safe and reachable with your passphrase.</p>
        <button class="btn btn-ghost" onclick="signOut()">Sign out / forget this device</button>
      </div>
      <div class="card">
        <p style="margin:0 0 6px"><b>Erase everything</b></p>
        <p class="muted tiny" style="margin:0 0 12px">Permanently deletes your account and all encrypted notes — here and on the server. This cannot be undone.</p>
        <button class="btn btn-emergency" onclick="confirmErase()">${I.trash} Erase all my data</button>
      </div>
    </div>
  </div>`);
};
function signOut(){
  // Show the "A moment for you" pause on the way out, but only if the user
  // actually did emotional work this session — otherwise it rings hollow. (NF-8)
  if(Session.didAssess){ Router.go('care','signout'); }
  else { finishSignOut(); }
}
function finishSignOut(){ Session.clearTrusted(); Session.lock(); toast('Signed out'); Router.go('welcome'); }
async function changeRole(id){ Session.profile.role=id; await persistProfile(); toast('Role updated'); Screens.settings(); }

/* PIN management card — adapts to whether a quick-unlock PIN exists on this device */
function pinCard(){
  const hasPin = !!(Session.trusted() && Session.trusted().wrap);
  if(hasPin){
    return `<div class="card">
      <p style="margin:0 0 6px"><b>Quick-unlock PIN</b></p>
      <p class="muted tiny" style="margin:0 0 12px">A PIN is set on this device for fast reopening. Your passphrase still works as a fallback, and is always required on a new device.</p>
      <button class="btn btn-ghost" onclick="Router.go('setpin')" style="margin-bottom:10px">Reset PIN</button>
      <button class="btn btn-quiet" onclick="confirmRemovePin()">Remove PIN from this device</button>
    </div>`;
  }
  return `<div class="card">
    <p style="margin:0 0 6px"><b>Quick-unlock PIN</b></p>
    <p class="muted tiny" style="margin:0 0 12px">Set a short PIN to reopen Aster quickly on this device, instead of retyping your passphrase. It’s stored only here and never sent anywhere.</p>
    <button class="btn btn-ghost" onclick="Router.go('setpin')">Set a quick PIN</button>
  </div>`;
}
function confirmRemovePin(){
  h(`<div class="screen">${topbar({back:"Router.go('settings')"})}
    <div class="scroll fadein">
      <h2>Remove the PIN?</h2>
      <p class="muted" style="margin-top:8px">You’ll unlock with your passphrase from now on, on this device. Your saved notes are not affected.</p>
      <div class="foot-actions">
        <button class="btn btn-ghost" onclick="removePin()">Remove PIN</button>
        <button class="btn btn-quiet" onclick="Router.go('settings')">Cancel</button>
      </div>
    </div></div>`);
}
function removePin(){ Session.clearTrusted(); toast('PIN removed'); Screens.settings(); }
function confirmErase(){
  h(`<div class="screen">${topbar({back:"Router.go('settings')"})}
    <div class="scroll fadein">
      <h2>Erase everything?</h2>
      <p class="muted" style="margin-top:8px">This deletes your account and every saved note, permanently, on all devices. There is no recovery.</p>
      <div class="foot-actions">
        <button class="btn btn-emergency" onclick="doErase()">Yes, erase it all</button>
        <button class="btn btn-quiet" onclick="Router.go('settings')">Cancel</button>
      </div>
    </div></div>`);
}
function doErase(){ Server.deleteAccount(Session.handle); Session.clearTrusted(); Session.lock(); toast('Everything erased'); Router.go('welcome'); }

/* ----------------------------------------------------------------------
   14. SOURCES & "what this won't do" (F-22, transparency / Criterion 1,2)
   ---------------------------------------------------------------------- */
Screens.sources = function(){
  h(`<div class="screen">
    ${topbar({back:"Router.go('home')"})}
    <div class="scroll fadein">
      <h2>How Aster works</h2>
      <div class="card" style="margin-top:16px">
        <p style="margin:0 0 8px"><b>It’s built on the public Singapore framework</b></p>
        <p class="muted tiny" style="margin:0">Aster is structured around the publicly documented child-protection pathway: the Sector-Specific Screening Guide (SSSG) used by frontline staff, and the Child Abuse Reporting Guide (CARG) used by trained colleagues. Aster does <b>not</b> reproduce those instruments — they’re training-gated and owned by MSF. Aster points you to them and to your trained colleague.</p>
      </div>
      <div class="card">
        <p style="margin:0 0 8px"><b>The risk level isn’t AI</b></p>
        <p class="muted tiny" style="margin:0">Your result comes from a fixed, transparent set of rules you can read — never a chatbot inventing an answer. The same answers always give the same result, and Aster always tells you why.</p>
      </div>
      <div class="card">
        <p style="margin:0 0 8px"><b>What Aster will never do</b></p>
        <p class="muted tiny" style="margin:0 0 6px">· Tell you an injury is or isn’t abuse</p>
        <p class="muted tiny" style="margin:0 0 6px">· File or send a report for you</p>
        <p class="muted tiny" style="margin:0 0 6px">· Ask you to confront the person you’re worried about</p>
        <p class="muted tiny" style="margin:0">· Collect your name, email, or anything that identifies you or the child</p>
      </div>
      <div class="card">
        <p style="margin:0 0 8px"><b>Your privacy, plainly</b></p>
        <p class="muted tiny" style="margin:0">We run a server so you can reach your notes across devices — but everything is encrypted on your device first, with a key only you hold. The server stores unreadable text. We can’t read your notes, and we don’t want to. We don’t claim to “store nothing” — we claim we can’t read what we store.</p>
      </div>
      <div class="card">
        <p style="margin:0 0 8px"><b>Official sources</b></p>
        <p class="tiny" style="margin:0 0 6px"><a class="link" href="https://www.msf.gov.sg/what-we-do/break-the-silence/for-professionals/child-abuse-reporting-tools" target="_blank" rel="noopener">MSF — Child Abuse Reporting Tools (SSSG &amp; CARG)</a></p>
        <p class="tiny" style="margin:0 0 6px"><a class="link" href="https://www.msf.gov.sg/what-we-do/break-the-silence/get-help/i-want-to-report-domestic-violence" target="_blank" rel="noopener">MSF — Report Domestic Violence (NAVH; good-faith immunity)</a></p>
        <p class="tiny" style="margin:0 0 6px"><a class="link" href="https://www.police.gov.sg/media-hub/news/2024/20240927_change_of_police_emergency_sms_sender_id_from_71999_to_70999" target="_blank" rel="noopener">SPF — Emergency SMS is now 70999 (not 71999)</a></p>
        <p class="tiny" style="margin:0"><a class="link" href="https://www.moe.gov.sg/news/parliamentary-replies/20230320-school-processes-on-managing-suspected-child-abuse-cases" target="_blank" rel="noopener">MOE — School processes for suspected child abuse</a></p>
      </div>
      <div class="note tiny" style="margin-bottom:24px">Before any real-world launch, confirm with SAFV/MSF exactly which guidance may be attributed and how. This prototype references the public framework only.</div>
    </div>
  </div>`);
};

/* ----------------------------------------------------------------------
   15. BOOT
   ---------------------------------------------------------------------- */
(function boot(){
  const accounts = Server.read();
  const hasAccount = Object.keys(accounts).length>0;
  let trusted = Session.trusted();

  // Only treat the device as PIN-trusted if the record is the current format
  // (has a `wrap`) AND its account still exists on this device's store.
  // Otherwise clear the stale record so we never show a PIN that was never set.
  if(trusted && (!trusted.wrap || !accounts[trusted.handle])){
    Session.clearTrusted();
    trusted = null;
  }

  if(trusted) Router.go('unlock');        // genuine PIN set on this device
  else if(hasAccount) Router.go('passphrase');
  else Router.go('welcome');
})();
