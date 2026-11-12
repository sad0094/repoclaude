'use strict';
/* Nöbet paneli. Ajanlardan gelen tüm metinler (cihaz adı, kullanıcı adı...) güvenilmezdir:
   h`...` şablonu araya giren her değeri varsayılan olarak kaçışlar. */
class Raw { constructor(s) { this.s = s; } }
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const one = (v) => (v instanceof Raw ? v.s : esc(v));
function h(strings, ...vals) {
  let out = '';
  strings.forEach((s, i) => { out += s; if (i < vals.length) out += Array.isArray(vals[i]) ? vals[i].map(one).join('') : one(vals[i]); });
  return new Raw(out);
}
const app = document.getElementById('app');
const ui = { me: null, totpSetup: null, recovery: null, company: localStorage.getItem('nobet.company') || '', companies: [], openCrit: 0,
  dlpHours: 24, auditArea: '', auditQuery: '', auditPages: [], alertSev: 'all', alertState: 'open', devStatus: 'all', devQuery: '', hostIssues: false, hours: 24, newToken: null };
let timer = null;

// ---------------------------------------------------------------- yardımcılar
async function api(path, body) {
  const res = await fetch(path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== '/api/login') { showLogin(); throw new Error('Oturum gerekli.'); }
  if (res.status === 403 && data.setup_2fa && ui.me && !ui.me.must_setup_2fa) { ui.me = null; setTimeout(render, 0); }
  if (!res.ok) { const err = new Error(data.error || 'İstek başarısız.'); err.data = data; throw err; }
  return data;
}
const scoped = (path, extra = {}) => {
  const p = new URLSearchParams(extra);
  if (ui.company) p.set('company', ui.company);
  const q = p.toString();
  return q ? `${path}?${q}` : path;
};
function toast(text) {
  document.querySelectorAll('.toast').forEach((t) => t.remove());
  const el = document.createElement('div');
  el.className = 'toast'; el.setAttribute('role', 'status'); el.textContent = text;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}
const nf = new Intl.NumberFormat('tr-TR');
const two = (n) => String(n).padStart(2, '0');
function fmtTime(ts) { const d = new Date(ts * 1000); return `${two(d.getDate())}.${two(d.getMonth() + 1)} ${two(d.getHours())}:${two(d.getMinutes())}`; }
function fmtClock(ts) { const d = new Date(ts * 1000); return `${two(d.getHours())}:${two(d.getMinutes())}`; }
function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec} sn`;
  if (sec < 3600) return `${Math.floor(sec / 60)} dk`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} sa ${Math.floor((sec % 3600) / 60)} dk`;
  return `${Math.floor(sec / 86400)} gün`;
}
const ago = (now, ts) => (ts ? `${fmtDur(now - ts)} önce` : 'hiç');
function fmtBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let i = 0; n = n || 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toLocaleString('tr-TR', { maximumFractionDigits: n < 10 && i ? 1 : 0 })} ${units[i]}`;
}
function fmtBps(n) {
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']; let i = 0; n = n || 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${n.toLocaleString('tr-TR', { maximumFractionDigits: n < 10 && i ? 1 : 0 })} ${units[i]}`;
}
const SEV = { crit: 'Kritik', warn: 'Uyarı', info: 'Bilgi' };
const ROLE = { admin: 'Yönetici', operator: 'Operatör', viewer: 'İzleyici' };
const canEdit = () => ui.me && ui.me.role !== 'viewer';
const isAdmin = () => ui.me && ui.me.role === 'admin';
const AUDIT = { 'auth.login': ['Giriş', 'ok'], 'auth.login_failed': ['Başarısız giriş', 'down'], 'auth.logout': ['Çıkış', 'info'], 'auth.password': ['Parola değişikliği', 'warn'], 'auth.totp_enabled': ['İki adım açıldı', 'ok'], 'auth.totp_disabled': ['İki adım kapatıldı', 'warn'],
  'alert.ack': ['Uyarı onayı', 'info'], 'device.watch': ['Cihaz izleme', 'info'], 'device.label': ['Cihaz adlandırma', 'info'],
  'check.create': ['Kontrol eklendi', 'info'], 'check.update': ['Kontrol değişti', 'info'], 'check.delete': ['Kontrol silindi', 'warn'],
  'user.create': ['Kullanıcı eklendi', 'warn'], 'user.update': ['Kullanıcı değişti', 'warn'], 'user.delete': ['Kullanıcı silindi', 'warn'],
  'company.create': ['Şirket eklendi', 'warn'], 'company.update': ['Şirket değişti', 'warn'], 'company.token': ['Anahtar yenilendi', 'warn'],
  'watch.create': ['Klasör izlemeye alındı', 'warn'], 'watch.delete': ['Klasör izlemesi kaldırıldı', 'warn'],
  'settings.update': ['Ayar değişti', 'warn'], 'settings.test': ['Test bildirimi', 'info'] };
const STATUS = { ok: 'Sağlıklı', warn: 'Uyarı', crit: 'Kritik', down: 'Çevrimdışı' };
const PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
  443: 'HTTPS', 445: 'SMB', 587: 'SMTP', 993: 'IMAPS', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5900: 'VNC', 6379: 'Redis', 8080: 'HTTP', 8443: 'HTTPS', 27017: 'MongoDB' };
const portName = (p) => (!p ? 'Windows oturumu' : PORTS[p] ? `${p} · ${PORTS[p]}` : String(p));
const badge = (cls, text) => h`<span class="badge b-${cls}">${text}</span>`;
const level = (v, warn = 70, crit = 85) => (v >= crit ? 'crit' : v >= warn ? 'warn' : '');
function meter(v) {
  if (v === null || v === undefined) return h`<span class="muted">—</span>`;
  return h`<div class="meter"><div class="bar"><i class="${level(v)}" style="width:${Math.min(100, v)}%"></i></div>%${Math.round(v)}</div>`;
}
const CHECK_STATE = { ok: ['ok', 'Çalışıyor'], warn: ['warn', 'Yavaş'], crit: ['down', 'Sorunlu'], unknown: ['off', 'Bekleniyor'], off: ['off', 'Kapalı'] };
const fmtMs = (v) => (v === null || v === undefined ? '—' : `${Math.round(v)} ms`);
function historyStrip(points) {
  // Son kontrollerin şeridi: mavi = başarılı, kırmızı ve kısa = başarısız (renk tek ipucu değil).
  if (!points.length) return h`<span class="muted small">—</span>`;
  const bars = points.map((p, i) => h`<rect x="${i * 5}" y="${p.ok ? 0 : 10}" width="4" height="${p.ok ? 20 : 10}" rx="1" fill="${p.ok ? '#5AA9FF' : '#FF7A6B'}"><title>${fmtTime(p.ts)} — ${p.ok ? fmtMs(p.latency_ms) : 'başarısız'}</title></rect>`);
  const failed = points.filter((p) => !p.ok).length;
  return h`<svg width="${points.length * 5}" height="20" role="img" aria-label="Son ${points.length} kontrolün ${failed} tanesi başarısız">${bars}</svg>`;
}
const empty = (text) => h`<div class="empty">${text}</div>`;
const pill = (act, value, current, label) => h`<button type="button" class="btn ${value === current ? 'on' : ''}" aria-pressed="${value === current}" data-act="${act}" data-value="${value}">${label}</button>`;

// ---------------------------------------------------------------- grafikler
function lineChart(series, { fmt, max, label }) {
  const W = 720, H = 220, L = 64, B = 200, T = 12;
  const all = series.flatMap((s) => s.points);
  if (all.length < 2) return empty('Grafik için henüz yeterli ölçüm yok.');
  const t0 = Math.min(...all.map((p) => p.t)), t1 = Math.max(...all.map((p) => p.t));
  const top = max || Math.max(1, ...all.map((p) => p.v)) * 1.15;
  const x = (t) => L + ((t - t0) / (t1 - t0 || 1)) * (W - L), y = (v) => B - (Math.min(v, top) / top) * (B - T);
  const grid = [0, 0.25, 0.5, 0.75, 1].map((f) => h`<line x1="${L}" x2="${W}" y1="${y(top * f)}" y2="${y(top * f)}" stroke="#262D38"/><text x="${L - 8}" y="${y(top * f) + 4}" text-anchor="end">${fmt(top * f)}</text>`);
  const lines = series.map((s) => {
    const d = s.points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`).join(' ');
    return h`<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2.5" stroke-linejoin="round" stroke-dasharray="${s.dash || ''}"/>`;
  });
  const mid = (t0 + t1) / 2;
  return h`<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${label}">${grid}${lines}</svg>
    <div class="axis" style="padding-left:${(L / W) * 100}%"><span>${fmtTime(t0)}</span><span>${fmtClock(mid)}</span><span>${fmtClock(t1)}</span></div>`;
}
function barChart(buckets, parts, label) {
  const W = 720, H = 200, B = 180, T = 10, L = 48;
  const top = Math.max(1, ...buckets.map((b) => parts.reduce((s, p) => s + (b[p.key] || 0), 0)));
  const bw = (W - L) / buckets.length;
  const bars = buckets.map((b, i) => {
    let base = B;
    const tip = `${fmtTime(b.t)} — ` + parts.map((p) => `${p.label}: ${nf.format(b[p.key] || 0)}`).join(', ');
    const rects = parts.map((p) => {
      const hgt = ((b[p.key] || 0) / top) * (B - T); base -= hgt;
      return h`<rect x="${(L + i * bw + 1).toFixed(1)}" y="${base.toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${hgt.toFixed(1)}" fill="${p.color}"/>`;
    });
    return h`<g><title>${tip}</title>${rects}</g>`;
  });
  return h`<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${label}">
    <line x1="${L}" x2="${W}" y1="${B}" y2="${B}" stroke="#262D38"/><line x1="${L}" x2="${W}" y1="${T}" y2="${T}" stroke="#262D38"/>
    <text x="${L - 8}" y="${T + 4}" text-anchor="end">${nf.format(top)}</text><text x="${L - 8}" y="${B + 4}" text-anchor="end">0</text>${bars}</svg>
    <div class="axis" style="padding-left:${(L / W) * 100}%"><span>${fmtTime(buckets[0].t)}</span><span>${fmtTime(buckets[buckets.length - 1].t)}</span></div>`;
}

// ---------------------------------------------------------------- iskelet
const NAV = [['', 'Genel Bakış'], ['hosts', 'Sunucular'], ['devices', 'Ağ Cihazları'], ['connections', 'Bağlantı Analizi'], ['services', 'Servisler'], ['dlp', 'Veri Koruma', false, true], ['alerts', 'Uyarılar'], ['users', 'Kullanıcılar', true], ['audit', 'İşlem Günlüğü', true], ['settings', 'Ayarlar', true], ['account', 'Hesabım']];
function shell(route, content) {
  const links = NAV.filter(([, , adminOnly, editorOnly]) => (!adminOnly || isAdmin()) && (!editorOnly || canEdit())).map(([id, label]) => h`<a class="nav ${route === id ? 'on' : ''}" href="#/${id}" ${route === id ? new Raw('aria-current="page"') : ''}><span>${label}</span>${id === 'alerts' && ui.openCrit ? h`<span class="count">${ui.openCrit}</span>` : ''}</a>`);
  const options = ui.companies.map((c) => h`<option value="${c.id}" ${String(c.id) === ui.company ? new Raw('selected') : ''}>${c.code} — ${c.name}</option>`);
  return h`<div class="shell"><nav class="side" aria-label="Ana menü">
    <div class="brand"><svg aria-hidden="true" width="26" height="26" viewBox="0 0 26 26" fill="none" stroke="#5AA9FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="13" cy="13" r="11"/><path d="M5 13h4l2-5 4 10 2-5h4"/></svg>Nöbet</div>
    <label for="company">Şirket</label><select id="company"><option value="">${ui.me && ui.me.all_companies ? 'Tüm şirketler' : 'Yetkili şirketlerim'}</option>${options}</select>
    ${links}<div class="spacer"></div><div class="small muted" style="padding:0 12px 8px">${ui.me ? h`${ui.me.username} · ${ROLE[ui.me.role]}` : ''}</div><button type="button" class="btn" data-act="logout">Oturumu kapat</button></nav>
    <main class="main" id="main">${content}</main></div>`;
}
function showLogin(error = '', pending = null) {
  clearTimeout(timer); ui.me = null;
  if (pending) {   // parola doğru, ikinci adım bekleniyor
    app.innerHTML = h`<div class="login"><form class="card" id="login-form">
      <div class="brand" style="padding:0">Nöbet</div><p class="muted" style="margin:0">Kimlik doğrulama uygulamanızdaki 6 haneli kodu girin. Telefonunuz yanınızda değilse kurtarma kodlarınızdan birini kullanın.</p>
      <input type="hidden" name="username" value="${pending.username}"><input type="hidden" name="password" value="${pending.password}">
      <label class="field"><span>Doğrulama kodu</span><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus maxlength="12"></label>
      <div class="error" role="alert">${error}</div><button class="btn primary">Doğrula</button><a href="#/" data-act="login-back" class="small">Farklı hesapla giriş yap</a></form></div>`.s;
    return;
  }
  app.innerHTML = h`<div class="login"><form class="card" id="login-form">
    <div class="brand" style="padding:0">Nöbet</div><p class="muted" style="margin:0">Merkezi yönetim paneline giriş yapın.</p>
    <label class="field"><span>Kullanıcı adı</span><input type="text" name="username" autocomplete="username" autocapitalize="none" required autofocus></label>
    <label class="field"><span>Parola</span><input type="password" name="password" autocomplete="current-password" required></label>
    <div class="error" role="alert">${error}</div><button class="btn primary">Giriş yap</button></form></div>`.s;
}

// ---------------------------------------------------------------- görünümler
function hostsTable(hosts, now) {
  if (!hosts.length) return empty(isAdmin() ? 'Henüz rapor gönderen sunucu yok. Ayarlar sayfasından şirket ekleyip ajanı kurun.' : 'Yetkili olduğunuz şirketlerde rapor gönderen sunucu yok.');
  const rows = hosts.map((x) => {
    const disk = x.disks.length ? Math.max(...x.disks.map((d) => d.pct)) : null;
    return h`<tr><td><a href="#/host/${x.id}"><b>${x.hostname}</b></a><div class="mono muted">${x.ip || '—'}</div></td>
      <td>${x.company_code}</td><td>${meter(x.online ? x.cpu : null)}</td><td>${meter(x.online ? x.mem_pct : null)}</td><td>${meter(disk)}</td>
      <td class="muted small">${ago(now, x.last_seen)}</td><td>${badge(x.status, STATUS[x.status])}</td></tr>`;
  });
  return h`<div class="scroll"><table style="min-width:760px"><thead><tr><th>Sunucu</th><th>Şirket</th><th>CPU</th><th>Bellek</th><th>Disk</th><th>Son rapor</th><th>Durum</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function alertItems(alerts, now, withAck = true) {
  if (!alerts.length) return empty('Açık uyarı yok.');
  return h`<ul class="list">${alerts.map((a) => h`<li>${badge(a.severity, SEV[a.severity])}
    <div><div class="title">${a.title}</div><div class="small muted">${a.company_code ? h`${a.company_code} · ` : ''}${a.hostname ? h`<a href="#/host/${a.host_id}">${a.hostname}</a> · ` : ''}${fmtTime(a.started_at)} başladı · ${a.resolved_at ? `${fmtDur(a.resolved_at - a.started_at)} sürdü` : `${fmtDur(now - a.started_at)} sürüyor`}</div>
    ${a.detail ? h`<div class="small muted">${a.detail}</div>` : ''}</div>
    ${!withAck || a.resolved_at ? '' : a.acked_at ? h`<span class="acked">Onaylandı${a.acked_by ? ` · ${a.acked_by}` : ''}</span>` : canEdit() ? h`<button type="button" class="btn line" data-act="ack" data-value="${a.id}">Onayla</button>` : h`<span class="muted small">Onay bekliyor</span>`}</li>`)}</ul>`;
}

const views = {
  async ''() {
    const d = await api(scoped('/api/overview')), k = d.kpis;
    ui.openCrit = k.alerts.crit;
    const down = k.hosts_total - k.hosts_online;
    const tiles = d.companies.map((c) => {
      const st = !c.hosts_total ? ['off', 'Ajan bekleniyor'] : c.hosts_online < c.hosts_total ? ['down', 'Sunucu çevrimdışı'] : c.crit ? ['crit', 'Kritik'] : c.warn ? ['warn', 'Uyarı'] : ['ok', 'Sağlıklı'];
      return h`<a class="tile" href="#/" data-act="company" data-value="${c.id}"><div class="wrap between"><b>${c.name}</b>${badge(st[0], st[1])}</div>
        <div class="small muted" style="margin-top:6px"><span class="mono">${c.code}</span> · ${c.hosts_online}/${c.hosts_total} sunucu · ${c.devices} ağ cihazı · ${c.crit} kritik, ${c.warn} uyarı</div></a>`;
    });
    const pts = (key) => d.traffic.map((p) => ({ t: p.t, v: p[key] || 0 }));
    return h`<header class="head"><div><h1>Genel Bakış</h1><p>${ui.company ? 'Seçili şirket' : 'Tüm şirketler'} · 15 saniyede bir yenilenir</p></div>
      <a class="btn primary" style="display:flex;align-items:center" href="#/alerts">Uyarıları incele</a></header>
    <section class="row" aria-label="Özet göstergeler">
      <div class="card kpi"><div class="label">Çevrimiçi sunucu</div><div class="value">${k.hosts_online}<small> / ${k.hosts_total}</small></div><div class="note ${down ? 't-crit' : ''}">${down ? `${down} sunucu yanıt vermiyor` : 'Tüm ajanlar rapor gönderiyor'}</div></div>
      <div class="card kpi"><div class="label">Ağ cihazı</div><div class="value">${k.devices_online}<small> / ${k.devices_total}</small></div><div class="note">Son taramada görülen / bilinen</div></div>
      <div class="card kpi"><div class="label">Açık uyarı</div><div class="value">${k.alerts.crit + k.alerts.warn + k.alerts.info}</div><div class="note"><span class="t-crit">${k.alerts.crit} kritik</span> · <span class="t-warn">${k.alerts.warn} uyarı</span> · ${k.alerts.info} bilgi</div></div>
      <div class="card kpi"><div class="label">Bağlantı denemesi (24 sa)</div><div class="value">${nf.format(k.attempts_24h)}</div><div class="note">${nf.format(k.closed_24h)} tanesi kapalı porta</div></div>
    </section>
    <section class="card"><h2>Şirketler</h2><div class="row" style="margin-top:14px;gap:12px">${tiles.length ? tiles : empty(isAdmin() ? 'Henüz şirket yok. Ayarlar sayfasından ekleyin.' : 'Size atanmış şirket yok. Yöneticinizden erişim isteyin.')}</div></section>
    ${d.checks.length ? h`<section class="card"><div class="wrap between"><h2>Servis durumu</h2><a class="small" href="#/services">Tümünü gör</a></div>
      <div class="row" style="margin-top:14px;gap:12px">${d.checks.slice(0, 12).map((k) => h`<a class="tile" style="flex-basis:170px" href="#/services"><b>${k.name}</b>
        <div class="small ${k.state === 'ok' ? 't-ok' : k.state === 'warn' ? 't-warn' : k.state === 'crit' ? 't-crit' : 'muted'}" style="margin-top:4px">${CHECK_STATE[k.state][1]}${k.state === 'ok' || k.state === 'warn' ? ` · ${fmtMs(k.latency_ms)}` : ''}</div>
        <div class="small muted">${k.company_code}</div></a>`)}</div></section>` : ''}
    <div class="row top"><section class="card grow2"><div class="wrap between"><h2>Ağ trafiği · son 24 saat</h2>
        <div class="legend"><span><i style="background:#5AA9FF"></i>Gelen</span><span><i style="background:#F2B84B"></i>Giden (kesikli)</span></div></div>
        ${lineChart([{ color: '#5AA9FF', points: pts('rx') }, { color: '#F2B84B', dash: '7 5', points: pts('tx') }], { fmt: fmtBps, label: 'Son 24 saatte gelen ve giden ağ trafiği' })}</section>
      <section class="card grow1"><div class="wrap between"><h2>Son uyarılar</h2><a class="small" href="#/alerts">Tümünü gör</a></div>${alertItems(d.alerts, d.now, false)}</section></div>
    <section class="card"><h2>Sunucular</h2><div style="margin-top:12px">${hostsTable(d.hosts, d.now)}</div></section>`;
  },

  async hosts() {
    const d = await api(scoped('/api/hosts'));
    const list = ui.hostIssues ? d.hosts.filter((x) => x.status !== 'ok') : d.hosts;
    return h`<header class="head"><div><h1>Sunucular</h1><p>Ajan kurulu sunucular · ${list.length} gösteriliyor</p></div>
      <div class="wrap" role="group" aria-label="Sunucu filtresi">${pill('host-filter', 'all', ui.hostIssues ? 'issues' : 'all', 'Tümü')}${pill('host-filter', 'issues', ui.hostIssues ? 'issues' : 'all', 'Yalnızca sorunlu')}</div></header>
      <section class="card">${hostsTable(list, d.now)}</section>`;
  },

  async host(id) {
    const d = await api(`/api/hosts/${id}`), x = d.host;
    const open = d.alerts.filter((a) => !a.resolved_at);
    const worst = open.find((a) => a.severity === 'crit');
    const tile = (label, value, pct, note) => h`<div class="card kpi ${level(pct || 0) === 'crit' ? 'crit' : ''}"><div class="label">${label}</div><div class="value">${value}</div>
      ${pct === null ? '' : h`<div class="bar wide"><i class="${level(pct)}" style="width:${Math.min(100, pct)}%"></i></div>`}<div class="note">${note}</div></div>`;
    const diskMax = x.disks.length ? Math.max(...x.disks.map((v) => v.pct)) : 0;
    const disks = x.disks.map((v) => h`<div><div class="wrap between"><span class="mono">${v.mount}</span><span class="mono ${level(v.pct) ? 't-' + level(v.pct) : ''}">%${Math.round(v.pct)}</span></div>
      <div class="bar wide"><i class="${level(v.pct)}" style="width:${v.pct}%"></i></div><div class="small muted">${fmtBytes(v.total - v.used)} boş · toplam ${fmtBytes(v.total)}</div></div>`);
    const pts = (key) => d.series.map((p) => ({ t: p.t, v: p[key] || 0 }));
    const capture = { sniffer: 'Tüm bağlantı denemeleri yakalanıyor', audit: 'Tüm bağlantı denemeleri güvenlik duvarı denetim kayıtlarından izleniyor', poll: 'Yalnızca kabul edilen bağlantılar izleniyor (ajan yetkisi kısıtlı)', off: 'Bağlantı yakalama kapalı' }[x.capture_mode] || '—';
    return h`<header class="head"><div><div class="small muted"><a href="#/hosts">Sunucular</a> / ${x.company_code} / ${x.hostname}</div>
        <div class="wrap" style="margin-top:6px"><h1>${x.hostname}</h1>${badge(x.status, STATUS[x.status])}</div>
        <p>${x.company_name} · <span class="mono">${x.ip || '—'}</span> · ${x.os || 'bilinmeyen işletim sistemi'} · ajan ${x.agent_version || '—'}</p></div>
      <a class="btn line" style="display:flex;align-items:center" href="#/connections" data-act="conn-host" data-value="${x.id}">Bağlantıları analiz et</a></header>
    ${worst ? h`<div class="banner" role="alert"><div><b>${worst.title}.</b> <span class="muted">${worst.detail || ''}</span></div><a href="#/alerts">Uyarıyı aç</a></div>` : ''}
    <section class="row" aria-label="Anlık kaynak kullanımı">
      ${tile('CPU', `%${Math.round(x.cpu || 0)}`, x.cpu || 0, `${x.cores || '?'} çekirdek · yük ${(x.load1 || 0).toFixed(2)}`)}
      ${tile('Bellek', `%${Math.round(x.mem_pct || 0)}`, x.mem_pct || 0, `${fmtBytes(x.mem_used)} / ${fmtBytes(x.mem_total)}`)}
      ${tile('En dolu disk', `%${Math.round(diskMax)}`, diskMax, `${x.disks.length} bölüm izleniyor`)}
      ${tile('Çalışma süresi', fmtDur(x.uptime_s || 0), null, `Son rapor ${ago(d.now, x.last_seen)}`)}</section>
    <div class="row"><section class="card grow2"><div class="wrap between"><h2>CPU ve bellek · son 24 saat</h2>
        <div class="legend"><span><i style="background:#5AA9FF"></i>CPU</span><span><i style="background:#F2B84B"></i>Bellek (kesikli)</span></div></div>
        ${lineChart([{ color: '#5AA9FF', points: pts('cpu') }, { color: '#F2B84B', dash: '7 5', points: pts('mem') }], { fmt: (v) => `%${Math.round(v)}`, max: 100, label: 'Son 24 saatte CPU ve bellek kullanımı' })}</section>
      <section class="card grow1" style="display:flex;flex-direction:column;gap:16px"><h2>Disk bölümleri</h2>${disks.length ? disks : empty('Disk bilgisi yok.')}</section></div>
    <div class="row"><section class="card grow2"><h2>Olay geçmişi</h2>${d.alerts.length ? alertItems(d.alerts, d.now, false) : empty('Bu sunucu için kayıtlı olay yok.')}</section>
      <section class="card grow1"><h2>Dinlenen portlar</h2><p class="small muted">${capture}</p>
        <div class="ports">${x.listening.length ? x.listening.map((p) => badge('info', portName(p))) : h`<span class="muted">Açık port yok.</span>`}</div>
        <p class="small muted" style="margin-bottom:0">Taranan alt ağlar: <span class="mono">${x.subnets.join(', ') || '—'}</span></p></section></div>`;
  },

  async devices() {
    const d = await api(scoped('/api/devices'));
    const q = ui.devQuery.toLowerCase();
    const list = d.devices.filter((x) => (ui.devStatus === 'all' || (ui.devStatus === 'online') === x.online)
      && (!q || [x.ip, x.mac, x.hostname, x.label, x.company_code].some((v) => (v || '').toLowerCase().includes(q))));
    const rows = list.map((x) => h`<tr><td>${x.unknown ? badge('off', 'Bilinmiyor') : x.online ? badge('ok', 'Çevrimiçi') : badge('down', 'Çevrimdışı')}</td>
      <td class="mono">${x.ip}</td><td><b>${x.label || x.hostname || '—'}</b>${x.is_gateway ? h` ${badge('info', 'Ağ geçidi')}` : ''}${x.label && x.hostname ? h`<div class="small muted">${x.hostname}</div>` : ''}</td>
      <td class="mono">${x.mac}</td><td>${x.company_code}<div class="small muted">${x.seen_by} gördü</div></td>
      <td class="small muted">${fmtTime(x.first_seen)}</td><td class="small muted">${ago(d.now, x.last_seen)}</td>
      <td>${canEdit() ? h`<div class="wrap"><button type="button" class="btn ${x.watched ? 'on' : ''}" aria-pressed="${!!x.watched}" data-act="watch" data-value="${x.id}" data-on="${x.watched ? 0 : 1}">${x.watched ? 'İzleniyor' : 'İzle'}</button>
        <button type="button" class="btn" data-act="label" data-value="${x.id}" data-label="${x.label}">Adlandır</button></div>` : x.watched ? badge('info', 'İzleniyor') : ''}</td></tr>`);
    return h`<header class="head"><div><h1>Ağ Cihazları</h1><p>Ajanların yerel ağda keşfettiği tüm cihazlar · ${list.length} / ${d.devices.length} gösteriliyor. "İzle" seçilen cihaz yanıt vermezse kritik uyarı üretilir.</p></div></header>
      <section class="card"><div class="wrap between"><label class="field" style="max-width:320px"><span class="sr">Cihaz ara</span><input type="search" id="dev-search" placeholder="IP, MAC veya ad ara" value="${ui.devQuery}"></label>
        <div class="wrap" role="group" aria-label="Durum filtresi">${pill('dev-status', 'all', ui.devStatus, 'Tümü')}${pill('dev-status', 'online', ui.devStatus, 'Çevrimiçi')}${pill('dev-status', 'offline', ui.devStatus, 'Çevrimdışı')}</div></div>
      ${rows.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:920px"><thead><tr><th>Durum</th><th>IP</th><th>Ad</th><th>MAC</th><th>Şirket</th><th>İlk görülme</th><th>Son görülme</th><th>İşlem</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Eşleşen cihaz yok. İlk ağ taraması ajan başladıktan birkaç saniye sonra gelir.')}</section>`;
  },

  async connections() {
    const extra = { hours: ui.hours }; if (ui.connHost) extra.host = ui.connHost;
    const d = await api(scoped('/api/connections', extra)), t = d.totals;
    const src = d.sources.map((s) => h`<tr><td class="mono">${s.src}</td><td>${s.internal ? badge('info', 'İç ağ') : badge('warn', 'Dış ağ')}</td>
      <td class="num">${nf.format(s.attempts)}</td><td class="num">${s.ports}</td><td class="num ${s.closed ? 't-crit' : ''}">${nf.format(s.closed)}</td>
      <td class="num ${s.ssh_fail ? 't-warn' : ''}">${nf.format(s.ssh_fail)}</td><td class="small muted">${ago(d.now, s.last)}</td></tr>`);
    const ports = d.ports.map((p) => h`<tr><td class="mono">${portName(p.port)}</td><td>${p.open ? badge('ok', 'Açık') : badge('down', 'Kapalı')}</td><td class="num">${nf.format(p.attempts)}</td><td class="num">${p.sources}</td></tr>`);
    const users = d.users.map((u) => h`<tr><td class="mono">${u.user}</td><td class="num">${nf.format(u.attempts)}</td><td class="num">${u.sources}</td></tr>`);
    const kind = (e) => (e.kind === 'ssh_fail' ? badge('warn', 'Giriş başarısız') : e.kind === 'ssh_ok' ? badge('ok', 'Başarılı giriş') : e.open ? badge('info', 'Bağlantı') : badge('down', 'Kapalı port'));
    const recent = d.recent.map((e) => h`<tr><td class="small muted">${fmtTime(e.ts)}</td><td>${kind(e)}</td><td class="mono">${e.src}</td><td class="mono">${portName(e.port)}${e.user ? h` · ${e.user}` : ''}</td><td>${e.hostname}<span class="muted small"> · ${e.company_code}</span></td><td class="num">${nf.format(e.count)}</td></tr>`);
    const parts = [{ key: 'open', label: 'Açık porta', color: '#5AA9FF' }, { key: 'closed', label: 'Kapalı porta', color: '#FF7A6B' }, { key: 'ssh_fail', label: 'Başarısız giriş', color: '#F2B84B' }];
    return h`<header class="head"><div><h1>Bağlantı Analizi</h1><p>Sunuculara gelen tüm bağlantı denemeleri${ui.connHost ? h` · tek sunucu filtresi açık (<a href="#/connections" data-act="conn-host" data-value="">kaldır</a>)` : ''}</p></div>
      <div class="wrap" role="group" aria-label="Zaman aralığı">${pill('hours', '1', String(ui.hours), '1 saat')}${pill('hours', '24', String(ui.hours), '24 saat')}${pill('hours', '168', String(ui.hours), '7 gün')}</div></header>
    <section class="row" aria-label="Bağlantı özeti">
      <div class="card kpi"><div class="label">Bağlantı denemesi</div><div class="value">${nf.format(t.attempts)}</div><div class="note">${t.sources} farklı kaynak</div></div>
      <div class="card kpi"><div class="label">Kapalı porta gelen</div><div class="value ${t.closed ? 't-crit' : ''}">${nf.format(t.closed)}</div><div class="note">Tarama veya yanlış yapılandırma işareti</div></div>
      <div class="card kpi"><div class="label">Başarısız oturum açma</div><div class="value ${t.ssh_fail ? 't-warn' : ''}">${nf.format(t.ssh_fail)}</div><div class="note">${nf.format(t.ssh_ok)} başarılı giriş</div></div></section>
    <section class="card"><div class="wrap between"><h2>Zaman içinde denemeler</h2><div class="legend">${parts.map((p) => h`<span><i style="background:${p.color}"></i>${p.label}</span>`)}</div></div>
      ${t.attempts + t.ssh_fail ? barChart(d.timeline, parts, 'Zaman içinde bağlantı denemeleri') : empty('Bu aralıkta kayıtlı bağlantı denemesi yok.')}</section>
    <div class="row"><section class="card grow2"><h2>En çok deneyen kaynaklar</h2>${src.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:620px"><thead><tr><th>Kaynak IP</th><th>Konum</th><th class="num">Deneme</th><th class="num">Port</th><th class="num">Kapalı</th><th class="num">Giriş hatası</th><th>Son</th></tr></thead><tbody>${src}</tbody></table></div>` : empty('Kayıt yok.')}</section>
      <section class="card grow1"><h2>Hedef portlar</h2>${ports.length ? h`<table style="margin-top:12px"><thead><tr><th>Port</th><th>Durum</th><th class="num">Deneme</th><th class="num">Kaynak</th></tr></thead><tbody>${ports}</tbody></table>` : empty('Kayıt yok.')}
        ${users.length ? h`<h2 style="margin-top:20px">Denenen kullanıcı adları</h2><table style="margin-top:12px"><thead><tr><th>Kullanıcı</th><th class="num">Deneme</th><th class="num">Kaynak</th></tr></thead><tbody>${users}</tbody></table>` : ''}</section></div>
    <section class="card"><h2>Son kayıtlar</h2>${recent.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:720px"><thead><tr><th>Zaman</th><th>Tür</th><th>Kaynak</th><th>Hedef</th><th>Sunucu</th><th class="num">Adet</th></tr></thead><tbody>${recent}</tbody></table></div>` : empty('Kayıt yok.')}</section>`;
  },

  async alerts() {
    const d = await api(scoped('/api/alerts', { state: ui.alertState }));
    if (ui.alertState === 'open') ui.openCrit = d.alerts.filter((a) => a.severity === 'crit').length;
    const list = ui.alertSev === 'all' ? d.alerts : d.alerts.filter((a) => a.severity === ui.alertSev);
    const n = (s) => d.alerts.filter((a) => a.severity === s).length;
    return h`<header class="head"><div><h1>Uyarılar</h1><p>Kritik uyarılar Telegram'a anında gönderilir; onaylanana kadar belirli aralıklarla tekrarlanır.</p></div>
      <div class="wrap" role="group" aria-label="Durum">${pill('alert-state', 'open', ui.alertState, 'Açık')}${pill('alert-state', 'resolved', ui.alertState, 'Çözülenler')}</div></header>
    <section class="row" aria-label="Uyarı özeti">
      <div class="card kpi"><div class="label">Kritik</div><div class="value t-crit">${n('crit')}</div></div>
      <div class="card kpi"><div class="label">Uyarı</div><div class="value t-warn">${n('warn')}</div></div>
      <div class="card kpi"><div class="label">Bilgi</div><div class="value">${n('info')}</div></div>
      <div class="card kpi"><div class="label">Onay bekleyen</div><div class="value">${d.alerts.filter((a) => !a.acked_at && !a.resolved_at).length}</div></div></section>
    <section class="card"><div class="wrap between"><h2>${ui.alertState === 'open' ? 'Açık uyarılar' : 'Çözülen uyarılar'} <span class="muted small" style="font-weight:400">· ${list.length} gösteriliyor</span></h2>
      <div class="wrap" role="group" aria-label="Önem derecesi">${pill('alert-sev', 'all', ui.alertSev, 'Tümü')}${pill('alert-sev', 'crit', ui.alertSev, 'Kritik')}${pill('alert-sev', 'warn', ui.alertSev, 'Uyarı')}${pill('alert-sev', 'info', ui.alertSev, 'Bilgi')}</div></div>
      ${list.length ? alertItems(list, d.now) : empty(ui.alertState === 'open' ? 'Açık uyarı yok.' : 'Çözülen uyarı yok.')}</section>`;
  },

  async settings() {
    const [c, s] = await Promise.all([api('/api/companies'), api('/api/settings')]);
    ui.companies = c.companies;
    const rows = c.companies.map((x) => h`<tr><td class="mono">${x.code}</td><td>${x.name}</td><td class="num">${x.hosts}</td><td class="mono muted">…${x.token_hint}</td>
      <td><form class="wrap" data-form="company-chat" data-id="${x.id}" style="flex-wrap:nowrap"><label class="sr" for="chat-${x.id}">Telegram sohbet kimliği</label><input type="text" id="chat-${x.id}" name="telegram_chat_id" value="${x.telegram_chat_id}" placeholder="varsayılan sohbet" style="min-width:140px"><button class="btn">Kaydet</button></form></td>
      <td><button type="button" class="btn" data-act="rotate" data-value="${x.id}" data-code="${x.code}">Anahtarı yenile</button></td></tr>`);
    const tokenBox = ui.newToken ? h`<div class="notice" role="status"><b>${ui.newToken.code} için ajan anahtarı</b> — yalnızca şimdi gösterilir, kaydedin:
      <p><code>${ui.newToken.token}</code></p><div class="small muted">Sunucuda kurulum:</div>
      <p><code>sudo ./agent/install.sh ${location.origin} ${ui.newToken.token}</code></p><div class="small muted">Windows sunucuda (yönetici PowerShell):</div>
      <p style="margin-bottom:0"><code>.\\agent\\windows\\install.ps1 -Manager ${location.origin} -Token ${ui.newToken.token} -EnableConnectionAudit</code></p></div>` : '';
    const num = (key, label) => h`<label class="field"><span>${label}</span><input type="number" min="0" step="1" name="${key}" value="${s[key]}"></label>`;
    return h`<header class="head"><div><h1>Ayarlar</h1><p>Şirketler, ajan anahtarları, bildirim kanalları ve uyarı eşikleri.</p></div></header>
    <section class="card" style="display:flex;flex-direction:column;gap:16px"><h2>Şirketler</h2>${tokenBox}
      ${rows.length ? h`<div class="scroll"><table style="min-width:820px"><thead><tr><th>Kod</th><th>Ad</th><th class="num">Sunucu</th><th>Anahtar</th><th>Telegram sohbeti</th><th>İşlem</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Henüz şirket yok.')}
      <form class="wrap" data-form="company-new" style="align-items:flex-end"><label class="field" style="flex:0 1 160px"><span>Kod</span><input type="text" name="code" placeholder="XXXX" required maxlength="24"></label>
        <label class="field"><span>Şirket adı</span><input type="text" name="name" placeholder="XXXX LTD Şirketi" required maxlength="120"></label><button class="btn primary">Şirket ekle</button></form></section>
    <form class="card" data-form="settings" style="display:flex;flex-direction:column;gap:16px"><h2>Acil durum bildirimleri</h2>
      ${s.last_notify_error ? h`<div class="error" role="alert">Son gönderim hatası: ${s.last_notify_error}</div>` : ''}
      <div class="row"><label class="field"><span>Telegram bot anahtarı ${s.telegram_bot_token_set ? `(kayıtlı: …${s.telegram_bot_token_hint})` : '(BotFather\'dan alınır)'}</span><input type="password" name="telegram_bot_token" autocomplete="off" placeholder="${s.telegram_bot_token_set ? 'değiştirmek için yeni anahtar girin' : '123456:ABC...'}"></label>
        <label class="field"><span>Varsayılan Telegram sohbet kimliği</span><input type="text" name="telegram_chat_id" value="${s.telegram_chat_id}" placeholder="-1001234567890"></label></div>
      <div class="row"><label class="field"><span>Webhook adresi (isteğe bağlı; Slack, Teams, çağrı servisi)</span><input type="text" name="webhook_url" value="${s.webhook_url}" placeholder="https://..."></label>
        <label class="field"><span>Panel adresi (bildirimlere bağlantı eklenir)</span><input type="text" name="panel_url" value="${s.panel_url}" placeholder="https://panel.example.com"></label></div>
      <div class="row">${num('reminder_minutes', 'Onaylanmayan kritik uyarıyı tekrarla (dakika, 0 = kapalı)')}
        <label class="check" style="flex:1 1 200px"><input type="checkbox" name="notify_warn" ${s.notify_warn >= 1 ? new Raw('checked') : ''}>"Uyarı" seviyesini de bildir</label></div>
      <h2>Oturum güvenliği</h2>
      <label class="check"><input type="checkbox" name="require_2fa" ${s.require_2fa >= 1 ? new Raw('checked') : ''}>Tüm kullanıcılar için iki adımlı doğrulamayı zorunlu tut (kurmayanlar kurana kadar paneli kullanamaz)</label>
      <h2>Uyarı eşikleri</h2>
      <div class="row">${num('disk_warn', 'Disk uyarı (%)')}${num('disk_crit', 'Disk kritik (%)')}${num('cpu_warn', 'CPU uyarı (%)')}${num('mem_warn', 'Bellek uyarı (%)')}</div>
      <div class="row">${num('offline_seconds', 'Sunucu çevrimdışı sayılma süresi (sn)')}${num('device_offline_seconds', 'İzlenen cihaz çevrimdışı süresi (sn)')}${num('scan_ports', 'Port taraması eşiği (10 dk içinde port)')}${num('brute_fails', 'Parola saldırısı eşiği (10 dk içinde hata)')}</div>
      <div class="row">${num('check_fail_count', 'Servis uyarısı için art arda başarısız kontrol')}${num('cert_warn_days', 'Sertifika uyarısı (kalan gün)')}</div>
      <h2>Veri koruma</h2>
      <div class="row">${num('usb_alert', 'USB takılınca uyar (1 = açık, 0 = kapalı)')}${num('dlp_delete_threshold', 'Toplu silme eşiği (10 dk, 0 = kapalı)')}${num('dlp_read_threshold', 'Toplu okuma eşiği (10 dk, 0 = kapalı)')}${num('dlp_retention_days', 'Kayıt saklama süresi (gün)')}</div>
      <div class="wrap"><button class="btn primary">Ayarları kaydet</button><button type="button" class="btn" data-act="test-notify">Test bildirimi gönder</button></div></form>`;
  },

  async services() {
    const [d, hd] = await Promise.all([api(scoped('/api/checks')), canEdit() ? api(scoped('/api/hosts')) : { hosts: [] }]);
    const n = (...states) => d.checks.filter((k) => states.includes(k.state)).length;
    const certSoon = d.checks.filter((k) => k.cert_days !== null && k.cert_days <= 30 && k.enabled).length;
    const rows = d.checks.map((k) => {
      const st = CHECK_STATE[k.state];
      const cert = k.cert_days === null ? h`<span class="muted">—</span>` : h`<span class="${k.cert_days <= 3 ? 't-crit' : k.cert_days <= 14 ? 't-warn' : ''}">${k.cert_days < 0 ? 'Süresi doldu' : `${Math.floor(k.cert_days)} gün`}</span>`;
      return h`<tr><td><b>${k.name}</b><div class="mono muted" style="overflow-wrap:anywhere">${k.target}</div>${k.detail && k.state !== 'ok' && k.state !== 'off' ? h`<div class="small ${k.state === 'crit' ? 't-crit' : 't-warn'}">${k.detail}</div>` : ''}</td>
        <td>${badge(st[0], st[1])}</td><td class="num">${k.state === 'off' || k.state === 'unknown' ? '—' : fmtMs(k.latency_ms)}</td>
        <td class="num">${k.uptime_24h === null ? '—' : `%${k.uptime_24h.toLocaleString('tr-TR')}`}</td><td>${cert}</td><td>${historyStrip(k.history)}</td>
        <td>${k.company_code}<div class="small muted">${k.hostname} · ${k.checked_at ? ago(d.now, k.checked_at) : 'henüz çalışmadı'}</div></td>
        ${canEdit() ? h`<td><div class="wrap" style="flex-wrap:nowrap"><button type="button" class="btn" data-act="check-toggle" data-value="${k.id}" data-on="${k.enabled ? 0 : 1}">${k.enabled ? 'Durdur' : 'Başlat'}</button>
          <button type="button" class="btn" data-act="check-delete" data-value="${k.id}" data-name="${k.name}">Sil</button></div></td>` : ''}</tr>`;
    });
    const form = !canEdit() ? '' : !hd.hosts.length ? h`<section class="card"><h2>Yeni kontrol</h2>${empty('Kontrol ekleyebilmek için önce bir sunucuya ajan kurulmalı.')}</section>` : h`<form class="card" data-form="check-new" style="display:flex;flex-direction:column;gap:12px"><h2>Yeni kontrol</h2>
      <p class="small muted" style="margin:0">Kontrolü seçtiğiniz sunucudaki ajan kendi ağının içinden çalıştırır; panele yalnızca durum ve yanıt süresi gelir.</p>
      <div class="row"><label class="field"><span>Ad</span><input type="text" name="name" required maxlength="80" placeholder="ERP uygulaması"></label>
        <label class="field" style="flex:0 1 190px"><span>Tür</span><select name="type"><option value="http">HTTP / HTTPS adresi</option><option value="tcp">TCP portu</option></select></label>
        <label class="field" style="flex:2 1 280px"><span>Hedef (adres veya sunucu:port)</span><input type="text" name="target" required maxlength="300" autocapitalize="none" placeholder="https://erp.sirket.local/ veya 10.0.0.5:5432"></label></div>
      <div class="row"><label class="field"><span>Çalıştıracak sunucu</span><select name="host_id">${hd.hosts.map((x) => h`<option value="${x.id}">${x.company_code} — ${x.hostname}</option>`)}</select></label>
        <label class="field" style="flex:0 1 220px"><span>Beklenen HTTP kodu</span><input type="number" name="expect_status" min="100" max="599" placeholder="200–399"></label>
        <label class="field" style="flex:0 1 220px"><span>Yavaş eşiği (ms)</span><input type="number" name="slow_ms" min="1" placeholder="isteğe bağlı"></label></div>
      <div class="wrap"><label class="check"><input type="checkbox" name="verify" checked>HTTPS sertifikasını doğrula</label><button class="btn primary">Kontrol ekle</button></div></form>`;
    return h`<header class="head"><div><h1>Servisler</h1><p>Ajanların her raporda çalıştırdığı sağlık kontrolleri. Art arda başarısız olan kontrol kritik uyarı üretir; süresi yaklaşan sertifikalar ayrıca bildirilir.</p></div></header>
    <section class="row" aria-label="Servis özeti">
      <div class="card kpi"><div class="label">Çalışan</div><div class="value t-ok">${n('ok', 'warn')}<small> / ${n('ok', 'warn', 'crit')}</small></div><div class="note">${n('warn')} tanesi yavaş</div></div>
      <div class="card kpi"><div class="label">Sorunlu</div><div class="value ${n('crit') ? 't-crit' : ''}">${n('crit')}</div><div class="note">${n('unknown', 'off')} kontrol beklemede veya kapalı</div></div>
      <div class="card kpi"><div class="label">Sertifikası 30 gün içinde dolan</div><div class="value ${certSoon ? 't-warn' : ''}">${certSoon}</div><div class="note">Yalnızca doğrulanan HTTPS kontrolleri</div></div></section>
    <section class="card"><h2>Kontroller</h2>${rows.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:${canEdit() ? 1080 : 900}px"><thead><tr><th>Servis</th><th>Durum</th><th class="num">Yanıt</th><th class="num">24 sa erişim</th><th>Sertifika</th><th>Son kontroller</th><th>Çalıştıran</th>${canEdit() ? h`<th>İşlem</th>` : ''}</tr></thead><tbody>${rows}</tbody></table></div>` : empty(canEdit() ? 'Henüz kontrol yok. Aşağıdan ekleyin.' : 'Henüz tanımlı kontrol yok.')}</section>
    ${form}`;
  },

  async audit() {
    // ui.auditPages: "daha eski" ile yüklenen sayfaların başlangıç kimlikleri (boşsa en yeni sayfa).
    const before = ui.auditPages[ui.auditPages.length - 1];
    const params = {}; if (ui.auditArea) params.area = ui.auditArea; if (ui.auditQuery) params.q = ui.auditQuery; if (before) params.before = before;
    const d = await api(scoped('/api/audit', params));
    const rows = d.entries.map((e) => { const a = AUDIT[e.action] || [e.action, 'info']; return h`<tr><td class="small muted" style="white-space:nowrap">${fmtTime(e.ts)}</td>
      <td><b>${e.username}</b>${e.role ? h`<div class="small muted">${ROLE[e.role] || e.role}</div>` : ''}</td><td>${badge(a[1], a[0])}</td>
      <td style="overflow-wrap:anywhere">${e.target}${e.detail ? h`<div class="small muted">${e.detail}</div>` : ''}</td><td>${e.company_code || h`<span class="muted">—</span>`}</td><td class="mono muted">${e.ip || '—'}</td></tr>`; });
    const last = d.entries[d.entries.length - 1];
    return h`<header class="head"><div><h1>İşlem Günlüğü</h1><p>Panelde yapılan her işlem: kim, ne zaman, hangi adresten. Kayıtlar değiştirilemez ve silinemez; bir yıl saklanır.</p></div></header>
    <section class="card"><div class="wrap between"><label class="field" style="max-width:320px"><span class="sr">Günlükte ara</span><input type="search" id="audit-search" placeholder="Kullanıcı, hedef veya IP ara" value="${ui.auditQuery}"></label>
      <div class="wrap" role="group" aria-label="İşlem alanı">${[['', 'Tümü'], ['auth', 'Oturum'], ['alert', 'Uyarı'], ['device', 'Cihaz'], ['check', 'Servis'], ['user', 'Kullanıcı'], ['company', 'Şirket'], ['settings', 'Ayar']].map(([v, l]) => pill('audit-area', v, ui.auditArea, l))}</div></div>
      ${rows.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:860px"><thead><tr><th>Zaman</th><th>Kullanıcı</th><th>İşlem</th><th>Hedef ve ayrıntı</th><th>Şirket</th><th>IP</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Eşleşen kayıt yok.')}
      <div class="wrap" style="margin-top:16px">${ui.auditPages.length ? h`<button type="button" class="btn" data-act="audit-newest">En yeniye dön</button>` : ''}${d.more ? h`<button type="button" class="btn" data-act="audit-older" data-value="${last.id}">Daha eski kayıtlar</button>` : ''}</div></section>`;
  },

  async dlp() {
    const [d, hd] = await Promise.all([api(scoped('/api/dlp', { hours: ui.dlpHours })), api(scoped('/api/hosts'))]);
    const t = d.totals;
    const ACT = { read: ['info', 'Okuma'], write: ['warn', 'Yazma'], create: ['info', 'Oluşturma'], delete: ['down', 'Silme'], move: ['warn', 'Taşıma'] };
    const who = (u) => (u ? h`<b>${u}</b>` : h`<span class="muted">Bilinmiyor</span>`);
    const usb = d.usb.map((e) => h`<tr><td class="small muted" style="white-space:nowrap">${fmtTime(e.ts)}</td><td>${e.action === 'insert' ? badge('warn', 'Takıldı') : badge('info', 'Çıkarıldı')}</td>
      <td><b>${e.device}</b>${e.detail ? h`<div class="small muted">${e.detail}</div>` : ''}</td><td>${e.hostname}<span class="muted small"> · ${e.company_code}</span></td></tr>`);
    const users = d.users.map((u) => h`<tr><td>${who(u.user)}</td><td class="num">${nf.format(u.reads)}</td><td class="num">${nf.format(u.writes)}</td>
      <td class="num ${u.deletes ? 't-crit' : ''}">${nf.format(u.deletes)}</td><td class="num">${u.paths}</td><td class="small muted">${ago(d.now, u.last)}</td></tr>`);
    const paths = d.paths.map((x) => h`<tr><td class="mono" style="overflow-wrap:anywhere">${x.path}</td><td class="num">${nf.format(x.total)}</td><td class="num">${x.users}</td></tr>`);
    const recent = d.recent.map((e) => h`<tr><td class="small muted" style="white-space:nowrap">${fmtTime(e.ts)}</td><td>${badge(ACT[e.action][0], ACT[e.action][1])}</td><td>${who(e.user)}</td>
      <td class="mono" style="overflow-wrap:anywhere">${e.path}</td><td>${e.hostname}<span class="muted small"> · ${e.company_code}</span></td><td class="num">${nf.format(e.count)}</td></tr>`);
    const watches = d.watch_paths.map((w) => h`<tr><td><span class="mono" style="overflow-wrap:anywhere">${w.path}</span>${w.label ? h`<div class="small muted">${w.label}</div>` : ''}</td>
      <td>${w.status === 'ok' ? badge('ok', 'İzleniyor') : w.status === 'error' ? badge('down', 'Sorun var') : badge('off', 'Ajan bekleniyor')}${w.detail ? h`<div class="small muted">${w.detail}</div>` : ''}</td>
      <td>${w.hostname}<span class="muted small"> · ${w.company_code}</span></td><td class="num">${nf.format(w.events_24h)}</td>
      <td><button type="button" class="btn" data-act="watch-delete" data-value="${w.id}" data-name="${w.path}">Kaldır</button></td></tr>`);
    return h`<header class="head"><div><h1>Veri Koruma</h1><p>USB depolama takılması ve hassas klasörlerdeki dosya işlemleri. Yalnızca dosya adı ve işlem türü kaydedilir; dosya içeriği okunmaz.</p></div>
      <div class="wrap" role="group" aria-label="Zaman aralığı">${pill('dlp-hours', '1', String(ui.dlpHours), '1 saat')}${pill('dlp-hours', '24', String(ui.dlpHours), '24 saat')}${pill('dlp-hours', '168', String(ui.dlpHours), '7 gün')}</div></header>
    <div class="notice small">Bu sayfa çalışanların dosya ve cihaz kullanımına ilişkin kayıtlar içerir. İzlemeye başlamadan önce ilgili şirkette çalışanların bilgilendirilmiş olması gerekir (KVKK). Kayıtlar Ayarlar'da belirlenen süre sonunda silinir; izleyici rolü bu sayfayı göremez.</div>
    <section class="row" aria-label="Özet">
      <div class="card kpi"><div class="label">USB depolama takılması</div><div class="value ${t.usb ? 't-warn' : ''}">${nf.format(t.usb)}</div><div class="note">Ajan kurulu sunucularda</div></div>
      <div class="card kpi"><div class="label">Dosya işlemi</div><div class="value">${nf.format(t.files)}</div><div class="note">${nf.format(t.reads)} okuma · ${nf.format(t.writes)} yazma</div></div>
      <div class="card kpi"><div class="label">Silme</div><div class="value ${t.deletes ? 't-crit' : ''}">${nf.format(t.deletes)}</div><div class="note">İzlenen klasörlerde</div></div>
      <div class="card kpi"><div class="label">İzlenen klasör</div><div class="value">${d.watch_paths.length}</div><div class="note">${d.watch_paths.filter((w) => w.status === 'error').length} tanesinde sorun var</div></div></section>
    <section class="card"><h2>İzlenen klasörler</h2>
      ${watches.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:780px"><thead><tr><th>Klasör</th><th>Durum</th><th>Sunucu</th><th class="num">24 sa işlem</th><th>İşlem</th></tr></thead><tbody>${watches}</tbody></table></div>` : empty('Henüz izlenen klasör yok.')}
      ${hd.hosts.length ? h`<form data-form="watch-new" class="row" style="margin-top:16px;align-items:flex-end"><label class="field" style="flex:2 1 300px"><span>Klasörün tam yolu</span><input type="text" name="path" required maxlength="260" autocapitalize="none" placeholder="D:\\Paylasim\\Muhasebe veya /srv/paylasim/muhasebe"></label>
        <label class="field"><span>Açıklama (isteğe bağlı)</span><input type="text" name="label" maxlength="80" placeholder="Muhasebe belgeleri"></label>
        <label class="field"><span>Sunucu</span><select name="host_id">${hd.hosts.map((x) => h`<option value="${x.id}">${x.company_code} — ${x.hostname}</option>`)}</select></label>
        <button class="btn primary">İzlemeye al</button></form>` : ''}</section>
    <section class="card"><h2>USB olayları</h2>${usb.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:520px"><thead><tr><th>Zaman</th><th>Olay</th><th>Aygıt</th><th>Sunucu</th></tr></thead><tbody>${usb}</tbody></table></div>` : empty('Bu aralıkta USB olayı yok.')}</section>
    <section class="card"><h2>En çok işlem gören dosyalar</h2>${paths.length ? h`<table style="margin-top:12px"><thead><tr><th>Dosya</th><th class="num">İşlem</th><th class="num">Kullanıcı</th></tr></thead><tbody>${paths}</tbody></table>` : empty('Kayıt yok.')}</section>
    <section class="card"><h2>Kullanıcılara göre dosya işlemleri</h2><p class="small muted" style="margin:4px 0 0">Kullanıcı adı yalnızca Windows sunucularda bilinir; Linux'ta "Bilinmiyor" görünür.</p>
      ${users.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:620px"><thead><tr><th>Kullanıcı</th><th class="num">Okuma</th><th class="num">Yazma</th><th class="num">Silme</th><th class="num">Dosya</th><th>Son</th></tr></thead><tbody>${users}</tbody></table></div>` : empty('Kayıt yok.')}</section>
    <section class="card"><h2>Son dosya işlemleri</h2>${recent.length ? h`<div class="scroll" style="margin-top:12px"><table style="min-width:820px"><thead><tr><th>Zaman</th><th>İşlem</th><th>Kullanıcı</th><th>Dosya</th><th>Sunucu</th><th class="num">Adet</th></tr></thead><tbody>${recent}</tbody></table></div>` : empty('Bu aralıkta dosya işlemi yok.')}</section>`;
  },

  async users() {
    const [u, c] = await Promise.all([api('/api/users'), api('/api/companies')]);
    const roleOptions = (current) => Object.keys(ROLE).map((r) => h`<option value="${r}" ${r === current ? new Raw('selected') : ''}>${ROLE[r]}</option>`);
    const companyBoxes = (x, prefix) => h`<label class="check"><input type="checkbox" name="all_companies" ${x.all_companies ? new Raw('checked') : ''}>Tüm şirketler</label>
      ${c.companies.map((co) => h`<label class="check"><input type="checkbox" name="companies" value="${co.id}" ${x.companies.includes(co.id) ? new Raw('checked') : ''}>${co.code}</label>`)}`;
    const cards = u.users.map((x) => h`<form class="card" data-form="user-edit" data-id="${x.id}" style="display:flex;flex-direction:column;gap:12px">
      <div class="wrap between"><div class="wrap"><h2>${x.username}</h2>${badge(x.role === 'admin' ? 'warn' : 'info', ROLE[x.role])}${x.totp_enabled ? badge('ok', 'İki adımlı') : ''}${x.active ? '' : badge('down', 'Devre dışı')}${x.id === ui.me.id ? badge('ok', 'Siz') : ''}</div>
        <span class="small muted">Son giriş: ${x.last_login ? fmtTime(x.last_login) : 'hiç'}</span></div>
      <div class="row"><label class="field" style="flex:0 1 200px"><span>Rol</span><select name="role">${roleOptions(x.role)}</select></label>
        <label class="field"><span>Yeni parola (değiştirmek için doldurun)</span><input type="password" name="password" autocomplete="new-password" minlength="8"></label></div>
      <fieldset style="border:0;margin:0;padding:0"><legend class="small muted">Erişebileceği şirketler (yönetici her zaman tümünü görür)</legend><div class="wrap">${companyBoxes(x, x.id)}</div></fieldset>
      <div class="wrap"><label class="check"><input type="checkbox" name="active" ${x.active ? new Raw('checked') : ''}>Hesap etkin</label>
        <button class="btn primary">Kaydet</button>${x.totp_enabled && x.id !== ui.me.id ? h`<button type="button" class="btn" data-act="user-reset-totp" data-value="${x.id}" data-name="${x.username}">İki adımı sıfırla</button>` : ''}${x.id === ui.me.id ? '' : h`<button type="button" class="btn" data-act="user-delete" data-value="${x.id}" data-name="${x.username}">Sil</button>`}</div></form>`);
    return h`<header class="head"><div><h1>Kullanıcılar</h1><p>Yönetici her şeyi yapar. Operatör atandığı şirketlerde uyarı onaylar ve cihaz izler. İzleyici atandığı şirketleri yalnızca görür.</p></div></header>
    <form class="card" data-form="user-new" style="display:flex;flex-direction:column;gap:12px"><h2>Yeni kullanıcı</h2>
      <div class="row"><label class="field"><span>Kullanıcı adı</span><input type="text" name="username" required minlength="3" maxlength="32" autocapitalize="none" autocomplete="off" placeholder="ornek.kullanici"></label>
        <label class="field"><span>Parola (en az 8 karakter)</span><input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
        <label class="field" style="flex:0 1 200px"><span>Rol</span><select name="role">${roleOptions('viewer')}</select></label></div>
      <fieldset style="border:0;margin:0;padding:0"><legend class="small muted">Erişebileceği şirketler</legend><div class="wrap">${companyBoxes({ all_companies: false, companies: [] }, 'new')}</div></fieldset>
      <div><button class="btn primary">Kullanıcı ekle</button></div></form>
    ${cards}`;
  },

  async account() {
    const names = ui.me.all_companies ? 'Tüm şirketler' : (ui.companies.map((c) => c.code).join(', ') || 'Atanmış şirket yok');
    return h`<header class="head"><div><h1>Hesabım</h1><p>${ui.me.username} · ${ROLE[ui.me.role]} · ${names}</p></div></header>
    <form class="card" data-form="password" style="display:flex;flex-direction:column;gap:16px;max-width:520px"><h2>Parola değiştir</h2>
      <label class="field"><span>Mevcut parola</span><input type="password" name="current" required autocomplete="current-password"></label>
      <label class="field"><span>Yeni parola (en az 8 karakter)</span><input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
      <p class="small muted" style="margin:0">Parolayı değiştirince diğer cihazlardaki oturumlarınız kapanır.</p>
      <div><button class="btn primary">Parolayı değiştir</button></div></form>
    ${twoFactorCard()}`;
  },
};
function twoFactorCard() {
  const me = ui.me, open = 'class="card" style="display:flex;flex-direction:column;gap:16px;max-width:520px"';
  if (ui.recovery) {
    return h`<section ${new Raw(open)}><h2>Kurtarma kodlarınız</h2><p class="muted" style="margin:0">İki adımlı doğrulama etkin. Telefonunuza erişemezseniz bu kodlarla giriş yapabilirsiniz; her kod bir kez kullanılır. <b>Bu kodlar bir daha gösterilmez</b>, güvenli bir yere kaydedin.</p>
      <div class="notice"><code>${ui.recovery.join('   ')}</code></div><div><button type="button" class="btn primary" data-act="recovery-done">Kaydettim</button></div></section>`;
  }
  if (me.totp_enabled) {
    return h`<form ${new Raw(open)} data-form="totp-disable"><div class="wrap"><h2>İki adımlı doğrulama</h2>${badge('ok', 'Etkin')}</div>
      <p class="muted" style="margin:0">Girişte paroladan sonra uygulama kodu istenir. Kullanılmamış kurtarma kodu: ${me.recovery_codes_left}.</p>
      <label class="field"><span>Parola</span><input type="password" name="password" required autocomplete="current-password"></label>
      <label class="field"><span>Uygulama kodu veya kurtarma kodu</span><input type="text" name="code" required autocomplete="one-time-code" maxlength="12"></label>
      <div><button class="btn">İki adımlı doğrulamayı kapat</button></div></form>`;
  }
  if (ui.totpSetup) {
    const grouped = ui.totpSetup.secret.replace(/(.{4})/g, '$1 ').trim();
    return h`<form ${new Raw(open)} data-form="totp-enable"><h2>İki adımlı doğrulama · kurulum</h2>
      <ol class="muted" style="margin:0;padding-left:20px"><li>Telefonunuzda bir kimlik doğrulama uygulaması açın (Google Authenticator, Microsoft Authenticator, Authy).</li>
        <li>"Kurulum anahtarı gir" seçeneğiyle aşağıdaki anahtarı ekleyin (tür: zaman tabanlı).</li><li>Uygulamanın gösterdiği 6 haneli kodu yazın.</li></ol>
      <div class="notice"><div class="small muted">Hesap: Nobet:${me.username}</div><code style="font-size:16px">${grouped}</code>
        <div class="small" style="margin-top:8px"><a href="${ui.totpSetup.uri}">Bu cihazdaki uygulamada aç</a></div></div>
      <label class="field"><span>6 haneli kod</span><input type="text" name="code" inputmode="numeric" required autocomplete="one-time-code" maxlength="7"></label>
      <div class="wrap"><button class="btn primary">Etkinleştir</button><button type="button" class="btn" data-act="totp-cancel">Vazgeç</button></div></form>`;
  }
  return h`<form ${new Raw(open)} data-form="totp-setup"><div class="wrap"><h2>İki adımlı doğrulama</h2>${badge(me.must_setup_2fa ? 'down' : 'off', me.must_setup_2fa ? 'Zorunlu' : 'Kapalı')}</div>
    <p class="muted" style="margin:0">${me.must_setup_2fa ? 'Yöneticiniz iki adımlı doğrulamayı zorunlu tuttu. Panelin geri kalanını kullanabilmek için kurulumu tamamlayın.' : 'Parolanız ele geçirilse bile hesabınıza girilememesi için telefonunuzdaki bir uygulamadan kod istenir.'}</p>
    <label class="field"><span>Parolanız</span><input type="password" name="password" required autocomplete="current-password"></label>
    <div><button class="btn primary">Kurulumu başlat</button></div></form>`;
}
const ADMIN_VIEWS = ['settings', 'users', 'audit'], STATIC_VIEWS = ['settings', 'users', 'account', 'audit'];

// ---------------------------------------------------------------- yönlendirme ve olaylar
function route() {
  if (ui.recovery) return { name: 'account' };   // kurtarma kodları kaydedilene kadar başka sayfaya geçilmez
  const [, name = '', arg] = location.hash.split('/'); return { name: views[name] && (!ADMIN_VIEWS.includes(name) || isAdmin()) && (name !== 'dlp' || canEdit()) ? name : '', arg }; }
async function render(auto = false) {
  clearTimeout(timer);
  if (!ui.me) { try { ui.me = await api('/api/me'); } catch (err) { return; } }
  const r = route();
  // Kullanıcı bir alana yazarken otomatik yenileme içeriği ezmesin.
  if (auto && (STATIC_VIEWS.includes(r.name) || (document.activeElement && ['INPUT', 'SELECT'].includes(document.activeElement.tagName)))) { timer = setTimeout(() => render(true), 15000); return; }
  try {
    if (ui.me.must_setup_2fa) {   // zorunlu kurulum: yalnızca hesap sayfası açılır
      const forced = await views.account();
      app.innerHTML = h`<div class="shell"><main class="main" id="main" style="max-width:720px;margin:0 auto"><div class="brand" style="padding:0">Nöbet</div>${forced}
        <div><button type="button" class="btn" data-act="logout">Oturumu kapat</button></div></main></div>`.s;
      return;
    }
    if (!ui.companies.length) ui.companies = (await api('/api/companies')).companies;
    if (ui.company && !ui.companies.some((c) => String(c.id) === ui.company)) ui.company = '';
    const content = await views[r.name](r.arg);
    const scroll = window.scrollY;
    app.innerHTML = shell(r.name === 'host' ? 'hosts' : r.name, content).s;
    if (auto) window.scrollTo(0, scroll);
  } catch (err) {
    if (err.message !== 'Oturum gerekli.') {
      if (!auto) app.innerHTML = shell(r.name, h`<div class="card"><h2>Yüklenemedi</h2><p class="muted">${err.message}</p><a href="#/">Genel Bakış'a dön</a></div>`).s;
    } else return;
  }
  timer = setTimeout(() => render(true), 15000);
}
const actions = {
  logout: async () => { await api('/api/logout', {}); showLogin(); },
  ack: async (v) => { await api(`/api/alerts/${v}/ack`, {}); },
  watch: async (v, el) => { await api(`/api/devices/${v}`, { watched: el.dataset.on === '1' }); },
  label: async (v, el) => { const text = prompt('Cihaz adı (boş bırakırsanız silinir):', el.dataset.label || ''); if (text !== null) await api(`/api/devices/${v}`, { label: text }); },
  company: (v) => { ui.company = String(v); localStorage.setItem('nobet.company', ui.company); },
  'conn-host': (v) => { ui.connHost = v; },
  'host-filter': (v) => { ui.hostIssues = v === 'issues'; },
  'dev-status': (v) => { ui.devStatus = v; },
  'alert-sev': (v) => { ui.alertSev = v; },
  'alert-state': (v) => { ui.alertState = v; },
  hours: (v) => { ui.hours = Number(v); },
  rotate: async (v, el) => {
    if (!confirm(`${el.dataset.code} için yeni anahtar üretilsin mi? Eski anahtarı kullanan ajanlar rapor gönderemez.`)) return;
    ui.newToken = { code: el.dataset.code, token: (await api(`/api/companies/${v}/token`, {})).token };
  },
  'dlp-hours': (v) => { ui.dlpHours = Number(v); },
  'watch-delete': async (v, el) => { if (!confirm(`${el.dataset.name} klasörünün izlenmesi kaldırılsın mı?`)) return false; await api(`/api/watchpaths/${v}/delete`, {}); },
  'login-back': () => { showLogin(); return false; },
  'totp-cancel': () => { ui.totpSetup = null; },
  'recovery-done': () => { ui.recovery = null; },
  'user-reset-totp': async (v, el) => { if (!confirm(`${el.dataset.name} için iki adımlı doğrulama sıfırlansın mı? Kullanıcının oturumları kapanır.`)) return false; await api(`/api/users/${v}`, { reset_totp: true }); toast('İki adımlı doğrulama sıfırlandı.'); },
  'audit-area': (v) => { ui.auditArea = v; ui.auditPages = []; },
  'audit-older': (v) => { ui.auditPages.push(v); },
  'audit-newest': () => { ui.auditPages = []; },
  'check-toggle': async (v, el) => { await api(`/api/checks/${v}`, { enabled: el.dataset.on === '1' }); },
  'check-delete': async (v, el) => { if (!confirm(`"${el.dataset.name}" kontrolü silinsin mi?`)) return false; await api(`/api/checks/${v}/delete`, {}); },
  'user-delete': async (v, el) => { if (!confirm(`${el.dataset.name} kullanıcısı silinsin mi?`)) return false; await api(`/api/users/${v}/delete`, {}); },
  'test-notify': async () => { const r = await api('/api/settings/test', {}); toast(`Test bildirimi gönderildi: ${r.sent.join(', ')}`); return false; },
};
document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-act]');
  if (!el) return;
  try { if ((await actions[el.dataset.act](el.dataset.value, el)) === false) return; } catch (err) { toast(err.message); return; }
  if (el.tagName !== 'A' || el.getAttribute('href') === location.hash) render();
});
document.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target, data = Object.fromEntries(new FormData(form));
  try {
    if (form.id === 'login-form') { await api('/api/login', data); ui.companies = []; ui.me = null; ui.totpSetup = null; ui.recovery = null; return render(); }
    if (form.dataset.form === 'totp-setup') { ui.totpSetup = await api('/api/me/totp_setup', data); }
    if (form.dataset.form === 'totp-enable') { ui.recovery = (await api('/api/me/totp_enable', data)).recovery_codes; ui.totpSetup = null; ui.me = null; }
    if (form.dataset.form === 'totp-disable') { await api('/api/me/totp_disable', data); ui.me = null; toast('İki adımlı doğrulama kapatıldı.'); }
    if (form.dataset.form === 'user-new' || form.dataset.form === 'user-edit') {
      const fd = new FormData(form);
      const body = { role: data.role, all_companies: !!form.all_companies.checked, companies: fd.getAll('companies').map(Number) };
      if (data.password) body.password = data.password;
      if (form.dataset.form === 'user-new') { body.username = data.username; await api('/api/users', body); toast('Kullanıcı eklendi.'); }
      else { body.active = form.active.checked; await api(`/api/users/${form.dataset.id}`, body); toast('Kullanıcı güncellendi.'); }
      if (form.dataset.id === String(ui.me.id)) ui.me = null;
    }
    if (form.dataset.form === 'watch-new') { data.host_id = Number(data.host_id); await api('/api/watchpaths', data); toast('Klasör izlemeye alındı; ajan bir sonraki raporda başlar.'); }
    if (form.dataset.form === 'check-new') { data.verify = form.verify.checked; data.host_id = Number(data.host_id); await api('/api/checks', data); toast('Kontrol eklendi; ilk sonuç bir sonraki ajan raporuyla gelir.'); }
    if (form.dataset.form === 'password') { await api('/api/me/password', data); toast('Parola değiştirildi.'); }
    if (form.dataset.form === 'company-new') { ui.newToken = await api('/api/companies', data); }
    if (form.dataset.form === 'company-chat') { await api(`/api/companies/${form.dataset.id}`, data); toast('Kaydedildi.'); }
    if (form.dataset.form === 'settings') { data.notify_warn = form.notify_warn.checked ? 1 : 0; data.require_2fa = form.require_2fa.checked ? 1 : 0; await api('/api/settings', data); toast('Ayarlar kaydedildi.'); }
    render();
  } catch (err) {
    if (form.id !== 'login-form') return toast(err.message);
    // Parola doğruysa ikinci adım ekranı açılır; ilk geçişte hata metni gösterilmez.
    if (err.data && err.data.totp_required) showLogin(data.code ? err.message : '', { username: data.username, password: data.password });
    else showLogin(err.message);
  }
});
document.addEventListener('change', (ev) => { if (ev.target.id === 'company') { actions.company(ev.target.value); render(); } });
document.addEventListener('input', (ev) => {
  const id = ev.target.id;
  if (id !== 'dev-search' && id !== 'audit-search') return;
  if (id === 'dev-search') ui.devQuery = ev.target.value; else { ui.auditQuery = ev.target.value; ui.auditPages = []; }
  clearTimeout(ui.searchTimer);
  ui.searchTimer = setTimeout(async () => { await render(); const box = document.getElementById(id); if (box) { box.focus(); box.setSelectionRange(box.value.length, box.value.length); } }, 250);
});
window.addEventListener('hashchange', () => render());
render();
