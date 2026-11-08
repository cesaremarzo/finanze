'use strict';
/* Finanze: i dati esistono in chiaro solo in memoria dopo lo sblocco.
   Sul dispositivo e su GitHub finisce solo testo cifrato (AES-256-GCM, chiave PBKDF2). */
const LS = { vault: 'fin.vault', dev: 'fin.device' };
const ITER = 600000, FILE = 'data.enc';
const LISTS = ['tx', 'bookings', 'accounts', 'recurring', 'planned'], SINGLE = ['settings', 'house'];
const AREAS = { personale: 'Personale', bnb: 'Casa vacanze', humfiverse: 'Humfiverse', cyberstand: 'Cyberstand' };
const CATS = {
  personale: { out: ['Casa e bollette', 'Spesa', 'Trasporti', 'Salute', 'Svago', 'Abbonamenti', 'Viaggi', 'Tasse e imposte', 'Altro'], in: ['Stipendio', 'Rimborsi', 'Altro'] },
  cyberstand: { out: ['Viaggi', 'Software', 'Altro'], in: ['Compenso', 'Altro'] },
  bnb: { out: ['Pulizie', 'Lavanderia', 'Utenze', 'Manutenzione', 'Forniture', 'Arredo', 'Tasse e imposte', 'Ritenute portali', 'Commercialista', 'Altro'], in: ['Affitto diretto', 'Altro'] },
  humfiverse: { out: ['Costituzione società', 'Legale', 'Contabilità', 'Hosting e software', 'Audit', 'Marketing', 'Viaggi', 'Altro'], in: ['Commissioni piattaforma', 'Finanziamenti', 'Altro'] },
};
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = new Intl.NumberFormat('it-IT', { style: 'currency', currency: 'EUR', maximumFractionDigits: 0 });
const fmt2 = new Intl.NumberFormat('it-IT', { style: 'currency', currency: 'EUR' });
const eur = n => fmt.format(n || 0), eur2 = n => fmt2.format(n || 0);
const num = v => { const n = parseFloat(v); return Number.isFinite(n) ? n : 0; };
const today = () => { const d = new Date(); return new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 10); };
const uid = () => [...crypto.getRandomValues(new Uint8Array(12))].map(b => b.toString(16).padStart(2, '0')).join('');
const b64 = b => { let s = ''; new Uint8Array(b).forEach(c => s += String.fromCharCode(c)); return btoa(s); };
const ub64 = s => Uint8Array.from(atob(s.replace(/\s/g, '')), c => c.charCodeAt(0));
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s);
const str = (v, n = 200) => String(v ?? '').slice(0, n);

let KEY = null, SALT = null, D = null, DEV = null;
const UI = { view: 'home', kind: 'out', area: 'personale', month: '', q: '', year: new Date().getFullYear(), sync: '' };

/* ---------- crittografia ---------- */
async function derive(pw, salt, iter = ITER) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, KEY, new TextEncoder().encode(JSON.stringify(obj)));
  return JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(SALT), iv: b64(iv), ct: b64(ct) });
}
async function open_(blob, key = KEY) {
  const o = typeof blob === 'string' ? JSON.parse(blob) : blob;
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(o.iv) }, key, ub64(o.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---------- modello dati ---------- */
function emptyDoc() {
  return {
    v: 1,
    settings: { u: 0, ral: 0, netAnnual: 0, mensilita: 13, addizionali: 2.3, units: [], taxRates: {}, budgets: {} },
    house: { u: 0, rate: 3.5, years: 30, ltv: 80, ratio: 30, otherDebts: 0, emergency: 6000, monthlySaving: 0, useBnb: false, catastalePct: 50, taxPct: 2, agencyPct: 3.66, fixedCosts: 4000 },
    tx: [], bookings: [], accounts: [], recurring: [], planned: [],
  };
}
function clean(raw) {
  const o = emptyDoc(); if (!raw || typeof raw !== 'object') return o;
  for (const k of SINGLE) if (raw[k] && typeof raw[k] === 'object') o[k] = { ...o[k], ...raw[k] };
  o.settings.units = (Array.isArray(o.settings.units) ? o.settings.units : []).map(u => str(u, 40));
  const base = r => ({ id: str(r.id || uid(), 80), u: num(r.u), ...(r.del ? { del: 1 } : {}) });
  const area = a => AREAS[a] ? a : 'personale', kind = k => k === 'in' ? 'in' : 'out', day = d => isDate(d) ? d : today();
  const map = {
    tx: r => ({ ...base(r), d: day(r.d), amt: Math.abs(num(r.amt)), kind: kind(r.kind), area: area(r.area), cat: str(r.cat, 40), unit: str(r.unit, 40), note: str(r.note) }),
    bookings: r => ({ ...base(r), arrive: day(r.arrive), depart: day(r.depart), nights: num(r.nights), unit: str(r.unit, 40), channel: str(r.channel, 30), gross: num(r.gross), comm: num(r.comm), net: num(r.net), cityTax: num(r.cityTax), note: str(r.note) }),
    accounts: r => ({ ...base(r), name: str(r.name, 60), balance: num(r.balance), d: day(r.d) }),
    recurring: r => ({ ...base(r), name: str(r.name, 60), amt: Math.abs(num(r.amt)), kind: kind(r.kind), area: area(r.area), cat: str(r.cat, 40), every: [1, 2, 3, 6, 12].includes(num(r.every)) ? num(r.every) : 1 }),
    planned: r => ({ ...base(r), name: str(r.name, 80), low: num(r.low), high: num(r.high), freq: r.freq === 'anno' ? 'anno' : 'una tantum', note: str(r.note) }),
  };
  for (const k of LISTS) o[k] = (Array.isArray(raw[k]) ? raw[k] : []).map(map[k]);
  return o;
}
function merge(a, b) {
  const o = emptyDoc();
  for (const k of SINGLE) o[k] = (b[k].u || 0) > (a[k].u || 0) ? b[k] : a[k];
  for (const k of LISTS) {
    const m = new Map();
    for (const r of [...a[k], ...b[k]]) { const c = m.get(r.id); if (!c || (r.u || 0) > (c.u || 0)) m.set(r.id, r); }
    o[k] = [...m.values()].sort((x, y) => x.id < y.id ? -1 : 1);
  }
  return o;
}
const live = k => D[k].filter(r => !r.del);
let persistT = null, syncT = null;
async function persist() { localStorage.setItem(LS.vault, await seal(D)); }
function changed() {
  clearTimeout(persistT); persistT = setTimeout(persist, 50);
  if (DEV) { clearTimeout(syncT); syncT = setTimeout(sync, 4000); }
}
function upsert(k, rec) {
  rec.u = Date.now();
  const i = D[k].findIndex(r => r.id === rec.id);
  if (i >= 0) D[k][i] = rec; else D[k].push(rec);
  changed();
}
function remove(k, id) {
  const r = D[k].find(x => x.id === id); if (!r) return;
  const before = { ...r }; r.del = 1; r.u = Date.now(); changed(); render();
  toast('Eliminato', 'Annulla', () => { Object.assign(r, before); delete r.del; r.u = Date.now(); changed(); render(); });
}

/* ---------- sincronizzazione su repository privato ---------- */
const ghURL = () => `https://api.github.com/repos/${DEV.repo}/contents/${FILE}`;
const ghH = accept => ({ Authorization: `Bearer ${DEV.token}`, Accept: accept || 'application/vnd.github+json' });
async function ghGet() {
  const r = await fetch(ghURL(), { headers: ghH(), cache: 'no-store' });
  if (r.status === 404) return { sha: null, text: null };
  if (!r.ok) throw new Error(r.status === 401 || r.status === 403 ? 'token non valido' : 'GitHub ' + r.status);
  const j = await r.json();
  if (j.content && j.encoding === 'base64') return { sha: j.sha, text: atob(j.content.replace(/\s/g, '')) };
  const raw = await fetch(ghURL(), { headers: ghH('application/vnd.github.raw+json'), cache: 'no-store' });
  if (!raw.ok) throw new Error('GitHub ' + raw.status);
  return { sha: j.sha, text: await raw.text() };
}
let syncing = false;
async function sync() {
  if (!DEV || syncing || !KEY) return;
  if (!navigator.onLine) { setSync('Offline: sincronizzo appena torna la rete'); return; }
  syncing = true; setSync('Sincronizzo…');
  try {
    for (let i = 0; i < 3; i++) {
      const { sha, text } = await ghGet();
      let remote = null;
      if (text) {
        try { remote = clean(await open_(text)); }
        catch { throw new Error('i dati online usano un’altra password: non li sovrascrivo'); }
      }
      const merged = remote ? merge(D, remote) : D;
      const same = remote && JSON.stringify(merged) === JSON.stringify(merge(remote, remote));
      const localChanged = JSON.stringify(merged) !== JSON.stringify(D);
      D = merged; await persist();
      if (localChanged) render();
      if (same) { setSync('Sincronizzato ' + new Date().toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })); return; }
      const body = { message: 'sync', content: btoa(await seal(D)) }; if (sha) body.sha = sha;
      const p = await fetch(ghURL(), { method: 'PUT', headers: { ...ghH(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (p.ok) { setSync('Sincronizzato ' + new Date().toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })); return; }
      if (p.status !== 409 && p.status !== 422) throw new Error(p.status === 401 || p.status === 403 ? 'token non valido' : 'GitHub ' + p.status);
    }
    throw new Error('conflitto, riprova');
  } catch (e) { setSync('Sync non riuscita: ' + e.message); }
  finally { syncing = false; }
}
function setSync(t) { UI.sync = t; const el = $('#syncState'); if (el) el.textContent = t; }

/* ---------- calcoli ---------- */
function flows() {
  /* Movimenti e prenotazioni con data futura sono previsioni, non cassa. */
  const now = today();
  const a = live('tx').filter(t => t.d <= now).map(t => ({ d: t.d, amt: t.amt, kind: t.kind, area: t.area, cat: t.cat }));
  for (const b of live('bookings')) if (b.depart <= now) a.push({ d: b.depart, amt: b.net, kind: 'in', area: 'bnb', cat: 'Prenotazioni' });
  return a;
}
function monthsBack(n) {
  const out = [], d = new Date(); d.setDate(1);
  for (let i = n - 1; i >= 0; i--) { const x = new Date(d.getFullYear(), d.getMonth() - i, 1); out.push(`${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}`); }
  return out;
}
const mLabel = m => new Date(+m.slice(0, 4), +m.slice(5) - 1, 1).toLocaleDateString('it-IT', { month: 'short' });
const liquidity = () => live('accounts').reduce((s, a) => s + a.balance, 0);
const monthlyEq = r => r.amt / r.every;
function bnbYear(y) {
  const units = {}; const blank = () => ({ gross: 0, comm: 0, net: 0, nights: 0, n: 0, tax: 0, costs: 0, cityTax: 0 });
  for (const b of live('bookings')) {
    if (!b.depart.startsWith(y)) continue;
    const u = units[b.unit] ||= blank();
    u.gross += b.gross; u.comm += b.comm; u.net += b.net; u.nights += b.nights; u.n++; u.cityTax += b.cityTax;
    u.tax += b.gross * num(D.settings.taxRates[b.unit]) / 100;
  }
  const common = blank(); let otherIn = 0, withheld = 0;
  const now = today(); let futureNet = 0, futureN = 0;
  for (const b of live('bookings')) if (b.depart.startsWith(y) && b.depart > now) { futureNet += b.net; futureN++; }
  for (const t of live('tx')) {
    if (t.area !== 'bnb' || !t.d.startsWith(y)) continue;
    if (t.kind === 'in') { otherIn += t.amt; continue; }
    /* La ritenuta è un acconto della cedolare, non un costo in più. */
    if (t.cat === 'Ritenute portali') { withheld += t.amt; continue; }
    const u = t.unit ? (units[t.unit] ||= blank()) : common; u.costs += t.amt;
  }
  const sum = f => Object.values(units).reduce((s, u) => s + u[f], 0);
  const tot = { gross: sum('gross'), comm: sum('comm'), net: sum('net'), nights: sum('nights'), n: sum('n'), tax: sum('tax'), cityTax: sum('cityTax'), costs: sum('costs') + common.costs, otherIn, withheld, futureNet, futureN };
  tot.result = tot.net + otherIn - tot.costs - tot.tax;
  return { units, common, tot };
}
function bnbMonthlyAvg() {
  const ms = new Set(monthsBack(12)); let s = 0;
  for (const f of flows()) if (f.area === 'bnb' && ms.has(f.d.slice(0, 7))) s += f.kind === 'in' ? f.amt : -f.amt;
  return s / 12;
}
function salaryMonthly() { return D.settings.netAnnual / 12; }
function plannedOut() {
  /* Le spese di casa vacanze sono già nella media netta del B&B. */
  return live('recurring').filter(r => r.kind === 'out' && r.area === 'personale').reduce((s, r) => s + monthlyEq(r), 0) +
    Object.values(D.settings.budgets).reduce((s, v) => s + num(v), 0);
}
function monthlySaving() {
  if (D.house.monthlySaving > 0) return D.house.monthlySaving;
  /* Senza spese previste il risparmio coinciderebbe con tutto lo stipendio: meglio non stimarlo. */
  return plannedOut() > 0 ? Math.max(0, salaryMonthly() + bnbMonthlyAvg() - plannedOut()) : 0;
}
/* Stima, da sostituire col cedolino. Aliquote e detrazioni 2026 per lavoro dipendente. */
function stimaNetto(ral, addizionali) {
  const contrib = ral * 0.0919, R = ral - contrib;
  let irpef = Math.min(R, 28000) * .23 + Math.max(0, Math.min(R, 50000) - 28000) * .33 + Math.max(0, R - 50000) * .43;
  let det = R <= 15000 ? 1955 : R <= 28000 ? 1910 + 1190 * (28000 - R) / 13000 : R <= 50000 ? 1910 * (50000 - R) / 22000 : 0;
  det += R > 20000 && R <= 32000 ? 1000 : R > 32000 && R <= 40000 ? 1000 * (40000 - R) / 8000 : 0;
  irpef = Math.max(0, irpef - det);
  return Math.round(ral - contrib - irpef - R * addizionali / 100);
}
function pmt(P, ratePct, years) { const i = ratePct / 1200, n = years * 12; return i ? P * i / (1 - (1 + i) ** -n) : P / n; }
function pv(rata, ratePct, years) { const i = ratePct / 1200, n = years * 12; return i ? rata * (1 - (1 + i) ** -n) / i : rata * n; }
function houseCalc() {
  const h = D.house, income = salaryMonthly() + (h.useBnb ? Math.max(0, bnbMonthlyAvg()) : 0);
  const maxRata = Math.max(0, income * h.ratio / 100 - h.otherDebts), maxLoan = pv(maxRata, h.rate, h.years);
  const ltv = h.ltv / 100, pct = h.catastalePct / 100 * h.taxPct / 100 + h.agencyPct / 100;
  const ceiling = ltv ? maxLoan / ltv : 0, available = Math.max(0, liquidity() - h.emergency), saving = monthlySaving();
  const byCash = (1 - ltv + pct) > 0 ? Math.max(0, available - h.fixedCosts) / (1 - ltv + pct) : 0;
  const scen = P => {
    const loan = P * ltv, cash = P * (1 - ltv) + P * pct + h.fixedCosts, miss = Math.max(0, cash - available);
    return { P, loan, rata: pmt(loan, h.rate, h.years), stress: pmt(loan, h.rate + 1, h.years), cash, miss, months: miss === 0 ? 0 : saving > 0 ? Math.ceil(miss / saving) : Infinity, ok: loan <= maxLoan };
  };
  return { income, maxRata, maxLoan, ceiling, available, saving, today: Math.min(ceiling, byCash), scen };
}

/* ---------- interfaccia ---------- */
const NAV = [['home', 'Panoramica'], ['add', 'Registra'], ['list', 'Movimenti'], ['bnb', 'Casa vacanze'], ['hf', 'Humfiverse'], ['house', 'Comprare casa'], ['set', 'Impostazioni']];
const NAVSHORT = { home: 'Home', add: 'Registra', list: 'Movimenti', bnb: 'B&B', hf: 'Humfi', house: 'Casa', set: 'Altro' };
function render() {
  const root = $('#app'), narrow = innerWidth < 800;
  const views = { home: vHome, add: vAdd, list: vList, bnb: vBnb, hf: vHf, house: vHouse, set: vSet };
  const nav = NAV.map(([k, l]) => `<button data-act="go" data-v="${k}" ${UI.view === k ? 'aria-current="page"' : ''}>${narrow ? NAVSHORT[k] : l}</button>`).join('');
  root.innerHTML = `<nav aria-label="Sezioni">${nav}</nav><main class="wrap"><div class="top"><h1>${esc(NAV.find(n => n[0] === UI.view)[1])}</h1><button class="sync" id="syncState" data-act="sync">${esc(UI.sync || (DEV ? '' : 'Non sincronizzato'))}</button></div>${views[UI.view]()}</main>`;
  drawChart();
}
const kpi = (l, v, cls = '') => `<div class="kpi"><b class="${cls}">${v}</b><span>${l}</span></div>`;
const opts = (arr, sel) => arr.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o]; return `<option value="${esc(v)}" ${v === sel ? 'selected' : ''}>${esc(l)}</option>`; }).join('');
const areaOpts = sel => opts(Object.entries(AREAS), sel);

function vHome() {
  const m = today().slice(0, 7), y = m.slice(0, 4), F = flows();
  const inM = F.filter(f => f.d.startsWith(m) && f.kind === 'in').reduce((s, f) => s + f.amt, 0);
  const outM = F.filter(f => f.d.startsWith(m) && f.kind === 'out').reduce((s, f) => s + f.amt, 0);
  const b = bnbYear(y), hc = houseCalc();
  const areas = Object.keys(AREAS).map(a => {
    const f = F.filter(x => x.area === a && x.d.startsWith(y));
    const i = f.filter(x => x.kind === 'in').reduce((s, x) => s + x.amt, 0), o = f.filter(x => x.kind === 'out').reduce((s, x) => s + x.amt, 0);
    return `<tr><td>${AREAS[a]}</td><td class="r num">${eur(i)}</td><td class="r num">${eur(o)}</td><td class="r num">${eur(i - o)}</td></tr>`;
  }).join('');
  const budgets = Object.entries(D.settings.budgets).filter(([, v]) => num(v) > 0).map(([c, v]) => {
    const spent = F.filter(f => f.area === 'personale' && f.kind === 'out' && f.cat === c && f.d.startsWith(m)).reduce((s, f) => s + f.amt, 0), over = spent > v;
    return `<div class="row small" style="justify-content:space-between"><span>${esc(c)}</span><span class="num">${eur(spent)} di ${eur(v)}${over ? ' · superato' : ''}</span></div><div class="meter"><i class="${over ? 'over' : ''}" style="width:${Math.min(100, spent / v * 100)}%"></i></div>`;
  }).join('');
  const setup = !D.settings.netAnnual || !live('accounts').length ? `<div class="note">Per completare il quadro inserisci stipendio e saldi dei conti in <button class="btn alt sm" data-act="go" data-v="set">Impostazioni</button></div>` : '';
  return `${setup}<div class="grid">${kpi('Liquidità sui conti', eur(liquidity()))}${kpi('Entrate del mese', eur(inM))}${kpi('Uscite del mese', eur(outM))}${kpi('Saldo del mese', eur(inM - outM))}</div>
  <section class="card"><h2>Ultimi 12 mesi</h2><div class="legend"><span><i style="background:var(--s1)"></i>Entrate</span><span><i style="background:var(--s2)"></i>Uscite</span></div><div class="chart" id="chart"></div>${chartTable()}</section>
  <section class="card"><h2>Anno ${y} per attività</h2><div class="tw"><table><thead><tr><th>Attività</th><th class="r">Entrate</th><th class="r">Uscite</th><th class="r">Saldo</th></tr></thead><tbody>${areas}</tbody></table></div>
  <p class="small mut" style="margin-top:10px">Da accantonare per la casa vacanze nel ${y}: ${eur(Math.max(0, b.tot.tax - b.tot.withheld))} di cedolare stimata al netto delle ritenute dei portali e ${eur(b.tot.cityTax)} di imposta di soggiorno.</p></section>
  ${expectedCard()}
  <section class="card"><h2>Comprare casa</h2><p class="num" style="font-size:1.25rem;font-weight:650;margin-bottom:2px">${eur(hc.ceiling)}</p><p class="mut small">prezzo massimo che il reddito sostiene con le impostazioni attuali. Con la liquidità di oggi arrivi a ${eur(hc.today)}.</p><button class="btn alt sm" data-act="go" data-v="house">Apri il simulatore</button></section>
  ${budgets ? `<section class="card"><h2>Budget del mese</h2>${budgets}</section>` : ''}`;
}
function expectedCard() {
  const now = today(), list = live('tx').filter(t => t.d > now).sort((a, b) => a.d < b.d ? -1 : 1);
  if (!list.length) return '';
  const sum = k => list.filter(t => t.kind === k).reduce((s, t) => s + t.amt, 0);
  return `<section class="card"><h2>Da incassare e da pagare</h2><p class="small mut num">Da incassare ${eur(sum('in'))} · da pagare ${eur(sum('out'))}</p>${list.map(t => `<div class="item"><div>${esc(t.note || t.cat)}<div class="small mut">${AREAS[t.area]} · entro il ${t.d.split('-').reverse().join('/')}</div></div><span class="num ${t.kind === 'in' ? 'in' : ''}">${t.kind === 'in' ? '+' : '−'}${eur2(t.amt)}</span></div>`).join('')}</section>`;
}
function chartData() {
  const ms = monthsBack(12), F = flows();
  return ms.map(m => { const f = F.filter(x => x.d.startsWith(m)); return { m, i: f.filter(x => x.kind === 'in').reduce((s, x) => s + x.amt, 0), o: f.filter(x => x.kind === 'out').reduce((s, x) => s + x.amt, 0) }; });
}
const chartTable = () => `<details><summary>Vedi come tabella</summary><div class="tw"><table><thead><tr><th>Mese</th><th class="r">Entrate</th><th class="r">Uscite</th></tr></thead><tbody>${chartData().map(d => `<tr><td>${mLabel(d.m)} ${d.m.slice(0, 4)}</td><td class="r num">${eur(d.i)}</td><td class="r num">${eur(d.o)}</td></tr>`).join('')}</tbody></table></div></details>`;
function niceMax(v) { if (v <= 0) return 100; const p = 10 ** Math.floor(Math.log10(v)); for (const s of [1, 2, 2.5, 5, 10]) if (s * p >= v) return s * p; return 10 * p; }
function drawChart() {
  const el = $('#chart'); if (!el) return;
  const data = chartData(), W = Math.max(280, el.clientWidth), H = 220, L = 46, B = 24, T = 8, plot = W - L - 4, ph = H - T - B;
  const max = niceMax(Math.max(...data.map(d => Math.max(d.i, d.o)))), y = v => T + ph - v / max * ph, step = plot / 12;
  const barW = Math.max(4, Math.min(16, step / 2 - 4));
  const bar = (x, v, c) => { const h = v / max * ph; if (h < 1) return ''; const r = Math.min(4, h, barW / 2), t = y(v); return `<path fill="var(${c})" d="M${x} ${T + ph}V${t + r}Q${x} ${t} ${x + r} ${t}H${x + barW - r}Q${x + barW} ${t} ${x + barW} ${t + r}V${T + ph}Z"/>`; };
  let s = '';
  for (let i = 0; i <= 4; i++) { const v = max * i / 4; s += `<line x1="${L}" x2="${W - 4}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v >= 1000 ? (v / 1000).toLocaleString('it-IT') + 'k' : v}</text>`; }
  data.forEach((d, i) => {
    const cx = L + step * i + step / 2;
    s += bar(cx - barW - 1, d.i, '--s1') + bar(cx + 1, d.o, '--s2');
    if (W >= 520 || i % 2 === 1) s += `<text x="${cx}" y="${H - 7}" text-anchor="middle">${mLabel(d.m).replace('.', '')}</text>`;
    s += `<rect data-tip="${i}" x="${L + step * i}" y="${T}" width="${step}" height="${ph}" fill="transparent"/>`;
  });
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="Entrate e uscite degli ultimi 12 mesi">${s}</svg>`;
  el.onpointermove = e => {
    const i = e.target.dataset?.tip, tip = $('#tip'); if (i === undefined) { tip.hidden = true; return; }
    const d = data[i]; tip.textContent = `${mLabel(d.m)} ${d.m.slice(0, 4)} · entrate ${eur(d.i)} · uscite ${eur(d.o)}`; tip.hidden = false;
    tip.style.top = Math.max(8, e.clientY - 44) + 'px'; tip.style.left = Math.min(innerWidth - tip.offsetWidth - 8, Math.max(8, e.clientX - tip.offsetWidth / 2)) + 'px';
  };
  el.onpointerleave = () => { $('#tip').hidden = true; };
}
function vAdd() {
  const { kind, area } = UI, cats = CATS[area][kind];
  return `<form class="card" data-form="tx">
  <div class="seg"><button type="button" data-act="kind" data-k="out" aria-pressed="${kind === 'out'}">Uscita</button><button type="button" data-act="kind" data-k="in" aria-pressed="${kind === 'in'}">Entrata</button></div>
  <label>Importo (€)<input name="amt" type="number" inputmode="decimal" step="0.01" min="0.01" required autofocus></label>
  <div class="f2"><label>Attività<select name="area" data-change="area">${areaOpts(area)}</select></label><label>Categoria<select name="cat">${opts(cats)}</select></label></div>
  <div class="f2"><label>Data<input name="d" type="date" value="${today()}" required></label>${area === 'bnb' ? `<label>Appartamento<select name="unit">${opts([['', 'Tutti / comune'], ...D.settings.units])}</select></label>` : '<span></span>'}</div>
  <label>Nota<input name="note" maxlength="200"></label>
  <button class="btn" style="width:100%">Salva</button></form>
  ${area === 'bnb' && kind === 'in' ? '<p class="note">Le prenotazioni si registrano nella sezione Casa vacanze. Qui vanno solo gli altri incassi, così non si contano due volte.</p>' : ''}
  ${recurringCard()}`;
}
function recurringCard() {
  const rows = live('recurring').map(r => `<div class="item"><div>${esc(r.name)}<div class="small mut">${AREAS[r.area]} · ${r.every === 1 ? 'ogni mese' : 'ogni ' + r.every + ' mesi'}</div></div><div class="row"><span class="num ${r.kind === 'in' ? 'in' : ''}">${r.kind === 'in' ? '+' : '−'}${eur2(r.amt)}</span><button class="btn alt sm" data-act="post" data-id="${r.id}">Registra</button><button class="x" aria-label="Elimina ${esc(r.name)}" data-act="del" data-k="recurring" data-id="${r.id}">×</button></div></div>`).join('');
  return `<section class="card"><h2>Voci ricorrenti</h2>${rows || '<p class="mut small">Stipendio, abbonamenti, bollette: si registrano con un tocco e alimentano le previsioni.</p>'}
  <details><summary>Aggiungi voce ricorrente</summary><form data-form="rec"><label>Nome<input name="name" required maxlength="60"></label><div class="f2"><label>Importo (€)<input name="amt" type="number" step="0.01" min="0.01" required></label><label>Tipo<select name="kind">${opts([['out', 'Uscita'], ['in', 'Entrata']])}</select></label><label>Attività<select name="area">${areaOpts('personale')}</select></label><label>Ogni<select name="every">${opts([['1', 'mese'], ['2', '2 mesi'], ['3', '3 mesi'], ['6', '6 mesi'], ['12', 'anno']])}</select></label></div><label>Categoria<input name="cat" maxlength="40" value="Altro"></label><button class="btn alt">Aggiungi</button></form></details></section>`;
}
function vList() {
  const q = UI.q.toLowerCase();
  const rows = live('tx').filter(t => (!UI.month || t.d.startsWith(UI.month)) && (!UI.areaF || t.area === UI.areaF) && (!q || (t.note + ' ' + t.cat + ' ' + t.unit).toLowerCase().includes(q))).sort((a, b) => a.d < b.d ? 1 : -1);
  const tot = rows.reduce((s, t) => s + (t.kind === 'in' ? t.amt : -t.amt), 0);
  return `<div class="card"><div class="f2"><label>Mese<input type="month" data-change="month" value="${UI.month}"></label><label>Attività<select data-change="areaF">${opts([['', 'Tutte'], ...Object.entries(AREAS)], UI.areaF || '')}</select></label></div><label>Cerca<input type="search" data-input="q" value="${esc(UI.q)}"></label><p class="small mut num" style="margin:0">${rows.length} movimenti · saldo ${eur2(tot)}</p></div>
  <section class="card">${rows.slice(0, 300).map(t => `<div class="item"><div>${esc(t.cat)}${t.unit ? ' · ' + esc(t.unit) : ''}<div class="small mut">${t.d.split('-').reverse().join('/')} · ${AREAS[t.area]}${t.note ? ' · ' + esc(t.note) : ''}</div></div><div class="row" style="flex-wrap:nowrap"><span class="num ${t.kind === 'in' ? 'in' : ''}">${t.kind === 'in' ? '+' : '−'}${eur2(t.amt)}</span><button class="x" aria-label="Elimina movimento" data-act="del" data-k="tx" data-id="${t.id}">×</button></div></div>`).join('') || '<p class="mut">Nessun movimento.</p>'}</section>`;
}
function vBnb() {
  const years = [...new Set([String(new Date().getFullYear()), ...live('bookings').map(b => b.depart.slice(0, 4))])].sort().reverse();
  const y = years.includes(String(UI.year)) ? String(UI.year) : years[0], { units, common, tot } = bnbYear(y);
  const uRows = Object.entries(units).sort().map(([n, u]) => `<tr><td>${esc(n || 'Senza appartamento')}</td><td class="r num">${u.n}</td><td class="r num">${u.nights}</td><td class="r num">${eur(u.gross)}</td><td class="r num">${eur(u.comm)}</td><td class="r num">${eur(u.net)}</td><td class="r num">${eur(u.costs)}</td><td class="r num">${eur(u.tax)}</td><td class="r num">${eur(u.net - u.costs - u.tax)}</td></tr>`).join('');
  const list = live('bookings').filter(b => b.depart.startsWith(y)).sort((a, b) => a.arrive < b.arrive ? 1 : -1);
  const unitsSel = D.settings.units.length ? opts(D.settings.units) : '';
  return `<div class="card"><label style="margin:0">Anno<select data-change="year">${opts(years, y)}</select></label></div>
  <div class="grid">${kpi('Incasso lordo', eur(tot.gross))}${kpi('Commissioni portali', eur(tot.comm))}${kpi('Costi di gestione', eur(tot.costs))}${kpi('Risultato dopo cedolare', eur(tot.result))}</div>
  <section class="card"><h2>Per appartamento</h2><div class="tw"><table><thead><tr><th>Alloggio</th><th class="r">Pren.</th><th class="r">Notti</th><th class="r">Lordo</th><th class="r">Commiss.</th><th class="r">Netto</th><th class="r">Costi</th><th class="r">Cedolare</th><th class="r">Risultato</th></tr></thead><tbody>${uRows || '<tr><td colspan="9" class="mut">Nessun dato per quest’anno.</td></tr>'}</tbody></table></div>
  <p class="small mut" style="margin-top:10px">Costi non assegnati a un appartamento: ${eur(common.costs)}. Altri incassi: ${eur(tot.otherIn)}. Imposta di soggiorno riscossa: ${eur(tot.cityTax)}, non è un guadagno. Cedolare stimata ${eur(tot.tax)}, di cui già trattenuta dai portali ${eur(tot.withheld)}: restano ${eur(Math.max(0, tot.tax - tot.withheld))}. È una stima con le aliquote impostate, da confermare col commercialista.${tot.futureN ? ` Il totale comprende ${tot.futureN} prenotazioni future per ${eur(tot.futureNet)} netti, non ancora incassate.` : ''}</p></section>
  <section class="card"><h2>Aggiungi prenotazione</h2><form data-form="book"><div class="f2"><label>Arrivo<input name="arrive" type="date" required></label><label>Partenza<input name="depart" type="date" required></label><label>Appartamento<select name="unit" required>${unitsSel}</select></label><label>Canale<select name="channel">${opts(['Booking', 'Airbnb', 'Diretto', 'Conoscenti', 'Altro'])}</select></label></div><div class="f4"><label>Lordo (€)<input name="gross" type="number" step="0.01" min="0" required></label><label>Commissioni (€)<input name="comm" type="number" step="0.01" min="0" value="0"></label><label>Imposta soggiorno (€)<input name="cityTax" type="number" step="0.01" min="0" value="0"></label><label>Nota<input name="note" maxlength="200"></label></div><button class="btn">Aggiungi</button></form>
  <details><summary>Importa da CSV</summary><p class="small mut">Accetta il registro prenotazioni e l’export pagamenti di Booking. I nomi degli ospiti vengono scartati.</p><input type="file" accept=".csv,text/csv" data-file="csv"></details></section>
  <section class="card"><h2>Prenotazioni ${y}</h2>${list.slice(0, 200).map(b => `<div class="item"><div>${esc(b.unit)} · ${esc(b.channel)}<div class="small mut">${b.arrive === b.depart ? 'Riepilogo' : b.arrive.split('-').reverse().join('/') + ' → ' + b.depart.split('-').reverse().join('/')} · ${b.nights} notti${b.note ? ' · ' + esc(b.note) : ''}</div></div><div class="row" style="flex-wrap:nowrap"><span class="num">${eur2(b.net)}</span><button class="x" aria-label="Elimina prenotazione" data-act="del" data-k="bookings" data-id="${b.id}">×</button></div></div>`).join('') || '<p class="mut">Nessuna prenotazione.</p>'}</section>`;
}
function vHf() {
  const y = String(new Date().getFullYear()), P = live('planned');
  const once = f => P.filter(p => p.freq === 'una tantum').reduce((s, p) => s + p[f], 0), yr = f => P.filter(p => p.freq === 'anno').reduce((s, p) => s + p[f], 0);
  const T = live('tx').filter(t => t.area === 'humfiverse'), spent = T.filter(t => t.kind === 'out').reduce((s, t) => s + t.amt, 0), spentY = T.filter(t => t.kind === 'out' && t.d.startsWith(y)).reduce((s, t) => s + t.amt, 0), inc = T.filter(t => t.kind === 'in').reduce((s, t) => s + t.amt, 0);
  const cats = {}; T.filter(t => t.kind === 'out').forEach(t => cats[t.cat] = (cats[t.cat] || 0) + t.amt);
  const range = (a, b) => a === b ? eur(a) : `${eur(a)}–${eur(b)}`;
  return `<div class="grid">${kpi('Avvio previsto', range(once('low'), once('high')))}${kpi('Costi annui previsti', range(yr('low'), yr('high')))}${kpi('Speso finora', eur(spent))}${kpi('Speso nel ' + y, eur(spentY))}</div>
  <section class="card"><h2>Costi previsti</h2>${P.map(p => `<div class="item"><div>${esc(p.name)}<div class="small mut">${p.freq}${p.note ? ' · ' + esc(p.note) : ''}</div></div><div class="row" style="flex-wrap:nowrap"><span class="num">${range(p.low, p.high)}</span><button class="x" aria-label="Elimina ${esc(p.name)}" data-act="del" data-k="planned" data-id="${p.id}">×</button></div></div>`).join('') || '<p class="mut">Nessuna voce.</p>'}
  <details><summary>Aggiungi voce prevista</summary><form data-form="plan"><label>Voce<input name="name" required maxlength="80"></label><div class="f2"><label>Minimo (€)<input name="low" type="number" step="1" min="0" required></label><label>Massimo (€)<input name="high" type="number" step="1" min="0" required></label></div><label>Frequenza<select name="freq">${opts(['una tantum', 'anno'])}</select></label><label>Nota<input name="note" maxlength="200"></label><button class="btn alt">Aggiungi</button></form></details></section>
  <section class="card"><h2>Consuntivo</h2><div class="tw"><table><tbody>${Object.entries(cats).map(([c, v]) => `<tr><td>${esc(c)}</td><td class="r num">${eur2(v)}</td></tr>`).join('') || '<tr><td class="mut">Registra le spese scegliendo Humfiverse come attività.</td></tr>'}</tbody></table></div><p class="small mut" style="margin-top:10px">Entrate totali: ${eur(inc)}.</p></section>`;
}
function vHouse() {
  const h = D.house, field = (k, l, step = 1) => `<label>${l}<input type="number" step="${step}" min="0" value="${h[k]}" data-house="${k}"></label>`;
  return `<div id="houseOut">${houseOut()}</div>
  <section class="card"><h2>Ipotesi</h2><div class="f2">${field('rate', 'Tasso annuo (%)', .05)}${field('years', 'Durata (anni)')}${field('ltv', 'Quota finanziata (%)')}${field('ratio', 'Rata massima su reddito (%)')}${field('otherDebts', 'Altre rate al mese (€)')}${field('emergency', 'Fondo emergenza da non toccare (€)', 100)}${field('monthlySaving', 'Risparmio mensile (0 = calcolato) (€)', 10)}${field('catastalePct', 'Valore catastale su prezzo (%)')}${field('taxPct', 'Imposta di registro (%)', .5)}${field('agencyPct', 'Agenzia, IVA inclusa (%)', .01)}${field('fixedCosts', 'Notaio, perizia, istruttoria (€)', 100)}</div>
  <label><input type="checkbox" data-house-check="useBnb" ${h.useBnb ? 'checked' : ''}>Conta anche il reddito della casa vacanze</label>
  <p class="note">La banca di solito conta i redditi extra solo se dichiarati e stabili da almeno due anni, quindi di base il calcolo usa solo lo stipendio. Tasso e imposte sono punti di partenza da aggiornare con un preventivo reale. Sotto i 36 anni verifica il Fondo Garanzia Prima Casa, che può alzare la quota finanziata.</p></section>`;
}
function houseOut() {
  const c = houseCalc(), steps = [100, 130, 160, 200, 250].map(k => k * 1000);
  const when = s => s.months === 0 ? 'ora' : s.months === Infinity ? 'n.d.' : s.months < 24 ? s.months + ' mesi' : (s.months / 12).toFixed(1).replace('.', ',') + ' anni';
  return `<div class="grid">${kpi('Prezzo massimo da reddito', eur(c.ceiling))}${kpi('Comprabile con la liquidità di oggi', eur(c.today))}${kpi('Rata massima', eur(c.maxRata))}${kpi(c.saving ? 'Risparmio mensile usato' : 'Risparmio mensile: inserisci budget o valore', c.saving ? eur(c.saving) : 'n.d.')}</div>
  <section class="card"><h2>Quale prezzo</h2><div class="tw"><table><thead><tr><th>Prezzo</th><th class="r">Rata</th><th>Reddito</th><th class="r">Tempo</th><th class="r">Contanti servono</th><th class="r">Ti mancano</th><th class="r">Mutuo</th><th class="r">Rata con +1%</th></tr></thead><tbody>${steps.map(c.scen).map(s => `<tr><td class="num">${eur(s.P)}</td><td class="r num">${eur(s.rata)}</td><td>${s.ok ? 'Ok' : 'Oltre limite'}</td><td class="r num">${when(s)}</td><td class="r num">${eur(s.cash)}</td><td class="r num">${eur(s.miss)}</td><td class="r num">${eur(s.loan)}</td><td class="r num">${eur(s.stress)}</td></tr>`).join('')}</tbody></table></div><p class="small mut" style="margin-top:10px">Disponibile per l’acquisto: ${eur(c.available)}, cioè liquidità meno fondo emergenza. Reddito mensile considerato: ${eur(c.income)}.</p></section>`;
}
function vSet() {
  const s = D.settings, acc = live('accounts');
  return `<section class="card"><h2>Stipendio</h2><form data-form="salary"><div class="f2"><label>RAL (€)<input name="ral" type="number" step="1" min="0" value="${s.ral}"></label><label>Addizionali stimate (%)<input name="addizionali" type="number" step="0.1" min="0" value="${s.addizionali}"></label></div><label>Netto annuo (€)<input name="netAnnual" type="number" step="1" min="0" value="${s.netAnnual}"></label><div class="row"><button class="btn">Salva</button><button type="button" class="btn alt" data-act="estimate">Stima il netto dalla RAL</button></div></form><p class="small mut" style="margin-top:10px">La stima è approssimativa: appena puoi, usa il netto reale del cedolino o della CU.</p></section>
  <section class="card"><h2>Conti</h2>${acc.map(a => `<div class="item"><div>${esc(a.name)}<div class="small mut">aggiornato ${a.d.split('-').reverse().join('/')}</div></div><div class="row" style="flex-wrap:nowrap"><input style="width:120px;margin:0" type="number" step="0.01" value="${a.balance}" aria-label="Saldo ${esc(a.name)}" data-account="${a.id}"><button class="x" aria-label="Elimina ${esc(a.name)}" data-act="del" data-k="accounts" data-id="${a.id}">×</button></div></div>`).join('')}
  <form data-form="acc" style="margin-top:10px"><div class="f2"><label>Nuovo conto<input name="name" required maxlength="60"></label><label>Saldo (€)<input name="balance" type="number" step="0.01" required></label></div><button class="btn alt">Aggiungi</button></form></section>
  <section class="card"><h2>Budget mensili personali</h2><div class="f2">${CATS.personale.out.map(c => `<label>${esc(c)}<input type="number" step="10" min="0" value="${num(s.budgets[c])}" data-budget="${esc(c)}"></label>`).join('')}</div></section>
  <section class="card"><h2>Casa vacanze</h2><form data-form="units"><label>Appartamenti, separati da virgola<input name="units" value="${esc(s.units.join(', '))}"></label><button class="btn alt">Salva</button></form><div class="f2" style="margin-top:12px">${s.units.map(u => `<label>Cedolare ${esc(u)} (%)<input type="number" step="1" min="0" value="${num(s.taxRates[u])}" data-tax="${esc(u)}"></label>`).join('')}</div></section>
  <section class="card"><h2>Sincronizzazione</h2>${DEV ? `<p class="small">Collegato a <b>${esc(DEV.repo)}</b>.</p><div class="row"><button class="btn alt" data-act="sync">Sincronizza ora</button><button class="btn alt" data-act="unlink">Scollega</button></div>` : `<form data-form="link"><label>Repository privato (utente/nome)<input name="repo" required autocomplete="off" spellcheck="false"></label><label>Token GitHub<input name="token" type="password" required autocomplete="off"></label><button class="btn alt">Collega</button></form>`}</section>
  <section class="card"><h2>Dati e sicurezza</h2><div class="row"><button class="btn alt" data-act="backup">Scarica backup cifrato</button><label class="btn alt" style="margin:0;color:var(--ink);display:inline-flex;align-items:center">Importa dati<input type="file" accept=".json" data-file="json" hidden></label><button class="btn alt" data-act="lock">Blocca ora</button></div><p class="small mut" style="margin-top:10px">Se dimentichi la password i dati non sono recuperabili.</p></section>`;
}

/* ---------- azioni ---------- */
let toastT;
function toast(msg, label, fn) {
  const t = $('#toast'); t.innerHTML = `<span>${esc(msg)}</span>${label ? `<button>${esc(label)}</button>` : ''}`; t.hidden = false;
  if (label) t.querySelector('button').onclick = () => { t.hidden = true; fn(); };
  clearTimeout(toastT); toastT = setTimeout(() => t.hidden = true, 5000);
}
const A = {
  go: b => { UI.view = b.dataset.v; render(); scrollTo(0, 0); },
  kind: b => { UI.kind = b.dataset.k; render(); },
  del: b => remove(b.dataset.k, b.dataset.id),
  sync: () => DEV && sync(),
  lock: () => location.reload(),
  post: b => { const r = D.recurring.find(x => x.id === b.dataset.id); upsert('tx', { id: uid(), d: today(), amt: r.amt, kind: r.kind, area: r.area, cat: r.cat, unit: '', note: r.name }); toast('Registrato: ' + r.name); },
  estimate: () => { const f = $('[data-form=salary]'); f.netAnnual.value = stimaNetto(num(f.ral.value), num(f.addizionali.value)); },
  unlink: async () => { DEV = null; localStorage.removeItem(LS.dev); UI.sync = ''; render(); },
  backup: async () => { const u = URL.createObjectURL(new Blob([await seal(D)], { type: 'application/json' })), a = document.createElement('a'); a.href = u; a.download = `finanze-backup-${today()}.json`; a.click(); URL.revokeObjectURL(u); },
};
document.addEventListener('click', e => { const b = e.target.closest('[data-act]'); if (b && KEY) { A[b.dataset.act]?.(b, e); } });
const FORMS = {
  tx: f => { upsert('tx', { id: uid(), d: f.d.value, amt: num(f.amt.value), kind: UI.kind, area: f.area.value, cat: f.cat.value, unit: f.unit?.value || '', note: f.note.value.trim() }); toast('Salvato'); render(); },
  rec: f => { upsert('recurring', { id: uid(), name: f.name.value.trim(), amt: num(f.amt.value), kind: f.kind.value, area: f.area.value, cat: f.cat.value.trim() || 'Altro', every: num(f.every.value) }); render(); },
  book: f => {
    const n = Math.round((new Date(f.depart.value) - new Date(f.arrive.value)) / 864e5); if (n < 1) return toast('La partenza deve seguire l’arrivo');
    const gross = num(f.gross.value), comm = num(f.comm.value);
    upsert('bookings', { id: uid(), arrive: f.arrive.value, depart: f.depart.value, nights: n, unit: f.unit.value, channel: f.channel.value, gross, comm, net: gross - comm, cityTax: num(f.cityTax.value), note: f.note.value.trim() }); toast('Prenotazione aggiunta'); UI.year = +f.depart.value.slice(0, 4); render();
  },
  plan: f => { upsert('planned', { id: uid(), name: f.name.value.trim(), low: num(f.low.value), high: num(f.high.value), freq: f.freq.value, note: f.note.value.trim() }); render(); },
  acc: f => { upsert('accounts', { id: uid(), name: f.name.value.trim(), balance: num(f.balance.value), d: today() }); render(); },
  salary: f => { Object.assign(D.settings, { ral: num(f.ral.value), addizionali: num(f.addizionali.value), netAnnual: num(f.netAnnual.value), u: Date.now() }); changed(); toast('Salvato'); },
  units: f => { D.settings.units = f.units.value.split(',').map(s => s.trim()).filter(Boolean).slice(0, 20); D.settings.u = Date.now(); changed(); render(); },
  link: async f => {
    const repo = f.repo.value.trim(); if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return toast('Formato repository: utente/nome');
    DEV = { repo, token: f.token.value.trim() }; localStorage.setItem(LS.dev, await seal(DEV)); render(); await sync();
  },
};
document.addEventListener('submit', e => { const f = e.target.closest('[data-form]'); if (!f) return; e.preventDefault(); if (KEY) FORMS[f.dataset.form]?.(f); });
document.addEventListener('change', async e => {
  const t = e.target, d = t.dataset; if (!KEY) return;
  if (d.change) { UI[d.change] = t.value; if (d.change === 'year') UI.year = +t.value; render(); }
  if (d.house) { D.house[d.house] = num(t.value); D.house.u = Date.now(); changed(); $('#houseOut').innerHTML = houseOut(); }
  if (d.houseCheck) { D.house[d.houseCheck] = t.checked; D.house.u = Date.now(); changed(); $('#houseOut').innerHTML = houseOut(); }
  if (d.budget) { D.settings.budgets[d.budget] = num(t.value); D.settings.u = Date.now(); changed(); }
  if (d.tax) { D.settings.taxRates[d.tax] = num(t.value); D.settings.u = Date.now(); changed(); }
  if (d.account) { const a = D.accounts.find(x => x.id === d.account); upsert('accounts', { ...a, balance: num(t.value), d: today() }); toast('Saldo aggiornato'); }
  if (d.file === 'json' && t.files[0]) await importJSON(t.files[0]);
  if (d.file === 'csv' && t.files[0]) await importCSV(t.files[0]);
});
document.addEventListener('input', e => { if (e.target.dataset.input === 'q') { UI.q = e.target.value; const p = e.target.selectionStart; render(); const i = $('[data-input=q]'); i.focus(); i.setSelectionRange(p, p); } });
let rsT, lastW = innerWidth; addEventListener('resize', () => { if (innerWidth === lastW) return; lastW = innerWidth; clearTimeout(rsT); rsT = setTimeout(() => D && render(), 150); });

async function importJSON(file) {
  try {
    const j = JSON.parse(await file.text());
    if (j.ct) { D = merge(D, clean(await open_(j))); }
    else if (j.finanzeSeed === 1) {
      const inc = clean(j);
      for (const k of LISTS) inc[k].forEach(r => { if (!D[k].some(x => x.id === r.id)) D[k].push(r); });
      if (j.settings) for (const [k, v] of Object.entries(j.settings)) D.settings[k] = v;
      if (j.house) Object.assign(D.house, j.house);
      D.settings = clean(D).settings; D.settings.u = D.house.u = Date.now();
    } else throw 0;
    changed(); render(); toast('Dati importati');
  } catch { toast('File non valido o cifrato con un’altra password'); }
}
function parseCSV(t) {
  const rows = []; let row = [], cur = '', q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true; else if (c === ',' || c === ';') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); rows.push(row); row = []; cur = ''; } else if (c !== '\r') cur += c;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows;
}
const matchUnit = s => D.settings.units.find(u => s.toLowerCase().includes(u.toLowerCase())) || s.slice(0, 40);
const absn = v => Math.abs(num(v));
function csvToBookings(text) {
  const rows = parseCSV(text.replace(/^﻿/, '')), h = rows[0] || [], ix = n => h.indexOf(n), out = [];
  const nights = (a, b) => Math.round((new Date(b) - new Date(a)) / 864e5);
  if (ix('Type/Transaction type') >= 0) {
    for (const r of rows.slice(1)) {
      if (r[ix('Type/Transaction type')] !== 'Reservation' || r[ix('Reservation status')] !== 'ok') continue;
      const arrive = r[ix('Check-in date')], depart = r[ix('Check-out date')], gross = num(r[ix('Gross amount')]);
      const comm = absn(r[ix('Commission')]) + absn(r[ix('Payments by Booking.com fee')]) + absn(r[ix('Tax/VAT')]);
      /* Booking ripete il riferimento per le rettifiche a lordo zero: vanno sommate alla stessa prenotazione. */
      const id = 'bk-' + r[ix('Reference number')], net = num(r[ix('Transaction amount')]), prev = out.find(b => b.id === id);
      if (prev) { prev.gross += gross; prev.comm += comm; prev.net += net; continue; }
      out.push({ id, arrive, depart, nights: num(r[ix('Room nights')]) || nights(arrive, depart), unit: matchUnit(r[ix('Property name')]), channel: 'Booking', gross, comm, net, cityTax: 0, note: '' });
    }
  } else if (ix('data_arrivo') >= 0) {
    for (const r of rows.slice(1)) {
      const arrive = r[ix('data_arrivo')], depart = r[ix('data_partenza')]; if (!isDate(arrive) || !isDate(depart)) continue;
      const gross = num(r[ix('importo_lordo')]), comm = num(r[ix('commissioni')]), unit = matchUnit(r[ix('appartamento')]), channel = r[ix('canale')];
      out.push({ id: `reg-${arrive}-${unit}-${channel}-${gross}`, arrive, depart, nights: nights(arrive, depart), unit, channel, gross, comm, net: r[ix('netto')] ? num(r[ix('netto')]) : gross - comm, cityTax: num(r[ix('imposta_soggiorno_riscossa')]), note: '' });
    }
  } else return null;
  return out;
}
async function importCSV(file) {
  const list = csvToBookings(await file.text());
  if (!list) return toast('Formato CSV non riconosciuto');
  let n = 0; for (const b of list) if (!D.bookings.some(x => x.id === b.id && !x.del)) { upsert('bookings', b); n++; }
  render(); toast(`${n} prenotazioni importate`);
}

/* ---------- sblocco ---------- */
function lockView(msg = '') {
  const has = !!localStorage.getItem(LS.vault);
  $('#app').innerHTML = `<main class="lock"><h1 style="margin-bottom:6px">Finanze</h1>${has ? `<p class="mut">Inserisci la password per sbloccare i dati.</p><form class="card" id="unlock"><label>Password<input id="pw" type="password" required autofocus autocomplete="current-password"></label><div class="err">${esc(msg)}</div><button class="btn" style="width:100%">Sblocca</button></form>` : `<p class="mut">I dati vengono cifrati sul dispositivo. Se perdi la password non si possono recuperare.</p>
  <form class="card" id="create"><h2>Inizia da zero</h2><label>Password, almeno 12 caratteri<input id="pw1" type="password" minlength="12" required autocomplete="new-password"></label><label>Ripeti la password<input id="pw2" type="password" required autocomplete="new-password"></label><div class="err">${esc(msg)}</div><button class="btn" style="width:100%">Crea</button></form>
  <form class="card" id="join"><h2>Collega questo dispositivo</h2><label>Repository privato (utente/nome)<input id="repo" required autocomplete="off" spellcheck="false"></label><label>Token GitHub<input id="tok" type="password" required autocomplete="off"></label><label>Password<input id="pw3" type="password" required autocomplete="current-password"></label><button class="btn alt" style="width:100%">Collega</button></form>`}</main>`;
}
function enter() { render(); if (DEV) sync(); armLock(); }
const onLock = {
  async unlock(f) {
    const v = JSON.parse(localStorage.getItem(LS.vault)); busy(f);
    try {
      SALT = ub64(v.salt); KEY = await derive($('#pw').value, SALT, v.iter); D = clean(await open_(v));
      const dv = localStorage.getItem(LS.dev); if (dv) DEV = await open_(dv);
      enter();
    } catch { KEY = null; lockView('Password errata'); }
  },
  async create() {
    const a = $('#pw1').value, b = $('#pw2').value;
    if (a.length < 12) return lockView('Almeno 12 caratteri'); if (a !== b) return lockView('Le password non coincidono');
    SALT = crypto.getRandomValues(new Uint8Array(16)); KEY = await derive(a, SALT); D = emptyDoc(); await persist(); enter();
  },
  async join(f) {
    busy(f);
    try {
      const repo = $('#repo').value.trim(), token = $('#tok').value.trim(), pw = $('#pw3').value;
      if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error('Formato repository: utente/nome');
      DEV = { repo, token }; const { text } = await ghGet();
      if (!text) throw new Error('Nessun dato nel repository: prima crea i dati su un altro dispositivo');
      const o = JSON.parse(text); SALT = ub64(o.salt);
      const k = await derive(pw, SALT, o.iter);
      let doc; try { doc = await open_(o, k); } catch { throw new Error('Password errata'); }
      KEY = k; D = clean(doc); await persist(); localStorage.setItem(LS.dev, await seal(DEV)); enter();
    } catch (e) { DEV = null; KEY = null; lockView(e.message); }
  },
};
function busy(f) { const b = f.querySelector('button'); b.disabled = true; b.textContent = 'Attendi…'; }
document.addEventListener('submit', e => { if (onLock[e.target.id]) { e.preventDefault(); onLock[e.target.id](e.target); } });
/* Blocco automatico: dopo 10 minuti senza attività o 5 minuti in background. */
function armLock() {
  let idle, hiddenAt = 0; const reset = () => { clearTimeout(idle); idle = setTimeout(() => location.reload(), 6e5); };
  ['pointerdown', 'keydown'].forEach(ev => addEventListener(ev, reset)); reset();
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hiddenAt = Date.now();
    else if (hiddenAt && Date.now() - hiddenAt > 3e5) location.reload(); else if (DEV) sync();
  });
  addEventListener('online', () => DEV && sync());
}
if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js');
lockView();
