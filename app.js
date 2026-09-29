(() => {
  'use strict';

  const APP_VERSION = 'v1 (0.15)';
  const RETRO_KEY = 'fd_retro_2000s';
  const XP_TITLE_KEY = 'fd_xp_title';
  const LOGO = '/assets/filedrop-logo.png';
  const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
  const KEYS = {
    profile: 'fd_profile_v1',
    history: 'fd_history_v1',
    consent: 'fd_consent_v1',
    seenVersion: 'fd_seen_version',
    lastShare: 'fd_last_share',
  };

  const $ = id => document.getElementById(id);
  const state = {
    profile: null,
    file: null,
    share: null,
    people: [],
    selectedPerson: null,
    pendingDrop: null,
    inbox: [],
    route: '/',
    refreshPeopleTimer: null,
    toastTimer: null,
  };

  function uid() {
    if (crypto.randomUUID) return crypto.randomUUID().replace(/-/g, '').slice(0, 24);
    return Array.from(crypto.getRandomValues(new Uint8Array(18))).map(x => x.toString(16).padStart(2, '0')).join('');
  }

  function esc(value) {
    return String(value ?? '').replace(/[&<>'"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[ch]));
  }

  function loadJson(key, fallback) {
    try { const v = JSON.parse(localStorage.getItem(key)); return v ?? fallback; } catch { return fallback; }
  }

  function saveJson(key, value) { localStorage.setItem(key, JSON.stringify(value)); }

  function makeDefaultProfile() {
    return {
      userId: uid(),
      nickname: `Guest-${Math.floor(1000 + Math.random() * 9000)}`,
      avatar: null,
      visible: true,
      motion: true,
      compact: false,
      accent: 'ice',
      defaultExpiry: '3600000',
      defaultDownloads: '5',
    };
  }

  function getProfile() {
    const stored = loadJson(KEYS.profile, null);
    if (!stored?.userId) {
      const p = makeDefaultProfile();
      saveJson(KEYS.profile, p);
      return p;
    }
    return { ...makeDefaultProfile(), ...stored };
  }

  function setProfile(p) {
    state.profile = p;
    saveJson(KEYS.profile, p);
    applyProfile();
  }

  function applyProfile() {
    const p = state.profile;
    document.body.classList.toggle('compact', Boolean(p.compact));
    document.body.classList.toggle('no-motion', p.motion === false);
    document.documentElement.dataset.accent = p.accent || 'ice';
    $('profileName').value = p.nickname || '';
    $('profileVisible').checked = p.visible !== false;
    $('motionToggle').checked = p.motion !== false;
    $('compactToggle').checked = Boolean(p.compact);
    if ($('defaultExpirySelect')) $('defaultExpirySelect').value = p.defaultExpiry || '3600000';
    if ($('defaultDownloadsSelect')) $('defaultDownloadsSelect').value = p.defaultDownloads || '5';
    $('settingsPreviewName').textContent = p.nickname || 'Guest';
    $('headerAvatar').src = p.avatar || LOGO;
    $('settingsAvatar').src = p.avatar || LOGO;
    $('menuAvatar').src = p.avatar || LOGO;
    $('menuName').textContent = p.nickname || 'Guest';
    $('onlineDot').classList.toggle('online', p.visible !== false);
    document.querySelectorAll('.accent-dot').forEach(btn => btn.classList.toggle('active', btn.dataset.accent === (p.accent || 'ice')));
  }

  function toast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return '—';
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB'];
    let n = bytes / 1024;
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
    return `${n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2)} ${units[i]}`;
  }

  function timeLeft(expiresAt) {
    if (!expiresAt) return 'Never';
    const delta = expiresAt - Date.now();
    if (delta <= 0) return 'Expired';
    const mins = Math.ceil(delta / 60000);
    if (mins < 60) return `${mins} min`;
    const hrs = Math.ceil(mins / 60);
    if (hrs < 24) return `${hrs} hr`;
    return `${Math.ceil(hrs / 24)} d`;
  }

  function downloadLabel(maxDownloads, used = 0) {
    if (maxDownloads === null || typeof maxDownloads === 'undefined') return `Unlimited · ${used} used`;
    return `${Math.max(0, maxDownloads - used)} left · ${used} used`;
  }

  function virusLabel(result) {
    if (!result) return 'not scanned';
    if (result.status === 'known-clean') return 'known clean';
    if (result.status === 'flagged') return `flagged (${result.malicious || 0} malicious)`;
    if (result.status === 'unknown') return 'not indexed';
    if (result.status === 'not-configured') return 'hash only';
    return 'check recommended';
  }

  function showView(view) {
    document.querySelectorAll('.page-view').forEach(v => v.classList.remove('active'));
    const target = $(`${view}View`);
    if (target) target.classList.add('active');
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === view));
    $('profileMenu').classList.add('hidden');
    if (view === 'history') renderHistory();
    if (view === 'people') { renderInbox(); fetchPeople(); }
    if (view === 'settings') applyProfile();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function currentShareFromHistory() {
    const raw = localStorage.getItem(KEYS.lastShare);
    try { return raw ? JSON.parse(raw) : state.share; } catch { return state.share; }
  }

  function renderResult(share) {
    const mount = $('resultMount');
    if (!share) { mount.innerHTML = ''; return; }
    const vtUrl = share.sha256 ? `https://www.virustotal.com/gui/file/${encodeURIComponent(share.sha256)}` : 'https://www.virustotal.com/';
    const owner = share.owner?.name ? ` · ${esc(share.owner.name)}` : '';
    const risk = share.riskFlags?.length ? ` <span>${esc(share.riskFlags.join(' · '))}</span>` : '';
    mount.innerHTML = `
      <article class="result-card">
        <div class="result-card-head">
          <div><span class="section-label">03 / SHARE</span><h3>Your link is ready</h3></div>
          <span class="result-success">Released${owner}</span>
        </div>
        <div class="share-url-row"><div class="share-url" id="resultUrl">${esc(share.shareUrl)}</div><button class="ghost-btn" id="copyResultUrl" type="button">Copy</button></div>
        <div class="result-actions"><a href="${esc(share.shareUrl)}">Open link</a><button id="openPeopleFromResult" type="button">Drop to a person</button><button id="checkVirusFromResult" type="button">VirusTotal</button></div>
        <div class="result-security"><strong>Security preflight:</strong> SHA-256 ${esc(share.sha256 || '—')} · ${esc(virusLabel(share.virusCheck))}.${risk}</div>
      </article>`;
    $('copyResultUrl').onclick = () => copyText(share.shareUrl);
    $('openPeopleFromResult').onclick = () => showView('people');
    $('checkVirusFromResult').onclick = () => window.open(vtUrl, '_blank', 'noopener,noreferrer');
  }

  function renderHistory() {
    const list = $('historyList');
    const empty = $('historyEmpty');
    const history = loadJson(KEYS.history, []);
    if (!history.length) { list.innerHTML = ''; empty.classList.remove('hidden'); return; }
    empty.classList.add('hidden');
    list.innerHTML = history.map((item, index) => {
      const expiry = item.expiresAt ? timeLeft(item.expiresAt) : 'Never';
      const saved = item.saved ? '★' : '☆';
      return `<div class="history-item" data-index="${index}">
        <div class="file-symbol">${item.type === 'received' ? 'IN' : 'OUT'}</div>
        <div class="history-main"><strong>${esc(item.fileName)}</strong><span>${esc(item.type === 'received' ? `From ${item.senderName || 'another user'}` : item.createdLabel || 'Shared')} · ${esc(formatBytes(item.size))} · ${esc(expiry)}</span></div>
        <div class="history-actions"><button data-action="star" title="Save locally">${saved}</button>${item.shareUrl ? `<button data-action="copy">Copy</button><button data-action="open">Open</button>` : ''}<button data-action="delete">×</button></div>
      </div>`;
    }).join('');
    list.querySelectorAll('.history-item').forEach(row => {
      const i = Number(row.dataset.index);
      row.querySelectorAll('button').forEach(btn => btn.addEventListener('click', () => {
        const h = loadJson(KEYS.history, []);
        const item = h[i];
        if (!item) return;
        if (btn.dataset.action === 'star') item.saved = !item.saved;
        if (btn.dataset.action === 'copy' && item.shareUrl) copyText(item.shareUrl);
        if (btn.dataset.action === 'open' && item.shareUrl) window.location.href = item.shareUrl;
        if (btn.dataset.action === 'delete') h.splice(i, 1);
        saveJson(KEYS.history, h);
        renderHistory();
      }));
    });
  }

  function addHistory(item) {
    const history = loadJson(KEYS.history, []);
    history.unshift({ ...item, createdLabel: new Date().toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) });
    saveJson(KEYS.history, history.slice(0, 80));
  }

  function renderPeople() {
    const list = $('peopleList');
    const empty = $('peopleEmpty');
    if (!state.people.length) { list.innerHTML = ''; empty.classList.remove('hidden'); return; }
    empty.classList.add('hidden');
    list.innerHTML = state.people.map(person => `
      <div class="person-row">
        <img class="avatar" src="${person.avatar || LOGO}" alt="">
        <div class="person-meta"><strong>${esc(person.nickname)}</strong><span>${person.online ? 'Online now' : `Last seen ${timeAgo(person.lastSeen)}`}</span></div>
        <div class="person-status ${person.online ? 'online' : ''}"><i></i>${person.online ? 'online' : 'offline'}</div>
        <button class="drop-person-btn" data-person="${esc(person.userId)}">Drop</button>
      </div>`).join('');
    list.querySelectorAll('.drop-person-btn').forEach(btn => btn.addEventListener('click', () => {
      const p = state.people.find(x => x.userId === btn.dataset.person);
      if (p) openDropDialog(p);
    }));
  }

  function renderInbox() {
    const mount = $('inboxMount');
    const inbox = state.inbox || [];
    if (!inbox.length) {
      mount.innerHTML = `<article class="inbox-card"><div class="inbox-head"><div><span class="section-label">INBOX</span><h3>No pending drops</h3></div></div><div class="inbox-empty">Files dropped to you will appear here when your local profile is online.</div></article>`;
      return;
    }
    mount.innerHTML = `<article class="inbox-card"><div class="inbox-head"><div><span class="section-label">INBOX</span><h3>Files dropped to you</h3></div><span class="inbox-count">${inbox.length}</span></div><div class="inbox-items">${inbox.map((m, i) => `<div class="inbox-item"><img src="${m.sender?.avatar || LOGO}" alt=""><div><strong>${esc(m.fileName)}</strong><span>From ${esc(m.sender?.nickname || 'User')} · ${esc(formatBytes(m.size))} · ${esc(m.passwordRequired ? 'Password protected' : 'Direct download')}</span></div><button data-inbox="${i}">Open</button></div>`).join('')}</div></article>`;
    mount.querySelectorAll('[data-inbox]').forEach(btn => btn.addEventListener('click', () => {
      const m = state.inbox[Number(btn.dataset.inbox)];
      if (!m) return;
      addHistory({ type: 'received', fileName: m.fileName, size: m.size, shareUrl: `${location.origin}/${m.shareId}`, senderName: m.sender?.nickname || 'User', expiresAt: m.expiresAt });
      window.location.href = `/${m.shareId}`;
    }));
  }

  function timeAgo(ts) {
    const mins = Math.max(1, Math.round((Date.now() - ts) / 60000));
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.round(hrs / 24)}d ago`;
  }

  async function fetchPeople() {
    const q = $('peopleSearch').value.trim();
    try {
      const response = await fetch(`/api/people?q=${encodeURIComponent(q)}`, { cache: 'no-store' });
      const data = await response.json();
      state.people = Array.isArray(data.people) ? data.people.filter(p => p.userId !== state.profile.userId) : [];
      renderPeople();
    } catch {
      state.people = [];
      renderPeople();
    }
  }

  async function heartbeat() {
    if (!localStorage.getItem(KEYS.consent)) return;
    try {
      await fetch('/api/presence/heartbeat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: state.profile.userId, nickname: state.profile.nickname, avatar: state.profile.avatar, visible: state.profile.visible !== false }),
      });
      const inboxResponse = await fetch(`/api/inbox?userId=${encodeURIComponent(state.profile.userId)}`, { cache: 'no-store' });
      if (inboxResponse.ok) {
        const inboxData = await inboxResponse.json();
        if (Array.isArray(inboxData.messages) && inboxData.messages.length) {
          state.inbox = [...inboxData.messages, ...(state.inbox || [])].slice(0, 30);
          showIncomingBar(state.inbox[0]);
          renderInbox();
          state.inbox.forEach(m => addHistory({ type: 'received', fileName: m.fileName, size: m.size, shareUrl: `${location.origin}/${m.shareId}`, senderName: m.sender?.nickname || 'User', expiresAt: m.expiresAt }));
        }
      }
      $('onlineDot').classList.add('online');
    } catch {
      $('onlineDot').classList.remove('online');
    }
  }

  function showIncomingBar(message) {
    $('incomingAvatar').src = message?.sender?.avatar || LOGO;
    $('incomingTitle').textContent = `${message?.fileName || 'New file'} dropped`;
    $('incomingCopy').textContent = `From ${message?.sender?.nickname || 'another user'} · open People to review it.`;
    $('incomingBar').classList.remove('hidden');
  }

  function openDropDialog(person) {
    const share = currentShareFromHistory();
    if (!share?.id) { toast('Generate a share link first.'); showView('home'); return; }
    state.selectedPerson = person;
    state.pendingDrop = { share, person };
    $('dropTitle').textContent = `Drop this file to ${person.nickname}?`;
    $('dropCopy').textContent = person.online ? 'They will see the file in their inbox while they are online.' : 'They are offline right now. The drop can be queued while the service keeps their profile record.';
    $('dropFileName').textContent = share.originalName || 'Shared file';
    $('dropFileRules').textContent = `${formatBytes(share.size)} · ${downloadLabel(share.maxDownloads, share.downloadsUsed)} · ${share.expiresAt ? timeLeft(share.expiresAt) : 'No expiry'}`;
    $('dropModal').classList.remove('hidden');
  }

  async function confirmDrop() {
    const pending = state.pendingDrop;
    if (!pending) return;
    $('confirmDrop').disabled = true;
    try {
      const response = await fetch('/api/drop', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ senderId: state.profile.userId, recipientId: pending.person.userId, shareId: pending.share.id }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Drop failed.');
      $('dropModal').classList.add('hidden');
      toast(`Dropped to ${pending.person.nickname}.`);
    } catch (err) {
      toast(err.message);
    } finally {
      $('confirmDrop').disabled = false;
    }
  }

  function resetSettings() {
    $('expirySelect').value = '3600000';
    $('customExpiryWrap').classList.add('hidden');
    $('downloadsSelect').value = '5';
    $('customDownloadsWrap').classList.add('hidden');
    $('customDownloads').value = '';
    $('customExpiryWrap').classList.add('hidden');
    $('customExpiry').value = '';
    $('passwordEnabled').checked = false;
    $('passwordWrap').classList.add('hidden');
    $('passwordInput').value = '';
    $('deleteAfterDownload').checked = false;
  }

  function getUploadSettings() {
    let maxDownloads = $('downloadsSelect').value;
    if (maxDownloads === 'unlimited') maxDownloads = null;
    else if (maxDownloads === 'custom') maxDownloads = Number($('customDownloads').value);
    else maxDownloads = Number(maxDownloads);
    const expiresValue = $('expirySelect').value;
    const expiresMs = expiresValue === 'null' ? null : expiresValue === 'custom' ? Number($('customExpiry').value) * 60000 : Number(expiresValue);
    return {
      maxDownloads,
      expiresMs,
      deleteAfterDownload: $('deleteAfterDownload').checked,
      passwordEnabled: $('passwordEnabled').checked,
      password: $('passwordInput').value,
      ownerName: state.profile.nickname,
      ownerAvatar: state.profile.avatar,
    };
  }

  function encodeHeader(value) {
    return encodeURIComponent(String(value || ''));
  }

  function encodeSettings(settings) {
    const bytes = new TextEncoder().encode(JSON.stringify(settings));
    let binary = '';
    const step = 0x8000;
    for (let i = 0; i < bytes.length; i += step) binary += String.fromCharCode(...bytes.subarray(i, i + step));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function uploadWithProgress(file, settings) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');
      xhr.responseType = 'json';
      xhr.upload.addEventListener('progress', event => {
        if (!event.lengthComputable) return;
        const percent = Math.round((event.loaded / event.total) * 100);
        $('uploadState').textContent = `${percent}%`;
        $('securityState').textContent = percent >= 99 ? 'Upload complete. Running hash/security preflight…' : `Uploading directly to temporary storage… ${percent}%`;
      });
      xhr.addEventListener('load', () => {
        const body = xhr.response || {};
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new Error(body.error || `Upload failed (${xhr.status}).`));
      });
      xhr.addEventListener('error', () => reject(new Error('Network error during upload.')));
      xhr.addEventListener('abort', () => reject(new Error('Upload cancelled.')));
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.setRequestHeader('X-File-Name', encodeHeader(file.name));
      xhr.setRequestHeader('X-File-Type', file.type || 'application/octet-stream');
      xhr.setRequestHeader('X-FileDrop-Settings', encodeSettings(settings));
      xhr.send(file);
    });
  }

  async function uploadFile() {
    if (!state.file) { toast('Choose a file first.'); return; }
    if (state.file.size > MAX_FILE_BYTES) { toast('That file is larger than 2 GB.'); return; }
    const settings = getUploadSettings();
    if (settings.maxDownloads !== null && (!Number.isInteger(settings.maxDownloads) || settings.maxDownloads < 1 || settings.maxDownloads > 10000)) { toast('Use a download limit from 1 to 10,000.'); return; }
    if (settings.passwordEnabled && settings.password.length < 4) { toast('Password must contain at least 4 characters.'); return; }

    $('uploadBtn').disabled = true;
    $('uploadState').textContent = 'Uploading';
    $('securityState').textContent = 'Uploading securely…';
    try {
      const share = await uploadWithProgress(state.file, settings);
      state.share = share;
      saveJson(KEYS.lastShare, share);
      addHistory({ type: 'sent', fileName: share.originalName, size: share.size, shareUrl: share.shareUrl, expiresAt: share.expiresAt, sha256: share.sha256 });
      renderResult(share);
      $('securityState').textContent = `Preflight complete · SHA-256 ${share.sha256.slice(0, 18)}… · ${virusLabel(share.virusCheck)}`;
      $('uploadState').textContent = 'Ready';
      toast('Share link created.');
    } catch (err) {
      $('uploadState').textContent = 'Ready';
      $('securityState').textContent = 'SHA-256 check will run before the share is released.';
      toast(err.message);
    } finally {
      $('uploadBtn').disabled = false;
    }
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); toast('Copied to clipboard.'); }
    catch { toast('Copy is blocked by this browser.'); }
  }

  function setFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) { toast('Maximum file size is 2 GB.'); return; }
    state.file = file;
    $('fileName').textContent = file.name;
    $('fileSize').textContent = `${formatBytes(file.size)} · ${file.type || 'binary'}`;
    $('filePreview').classList.remove('hidden');
    $('dropzone').classList.add('has-file');
  }

  function clearFile() {
    state.file = null;
    $('fileInput').value = '';
    $('filePreview').classList.add('hidden');
    $('dropzone').classList.remove('has-file');
  }

  function handleRoute() {
    const path = location.pathname.replace(/\/$/, '') || '/';
    state.route = path;
    if (path !== '/' && /^\/[A-Za-z0-9]{4,32}$/.test(path)) {
      document.querySelectorAll('.page-view').forEach(v => v.classList.remove('active'));
      $('shareView').classList.add('active');
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      loadShare(path.slice(1));
    } else {
      showView('home');
    }
  }

  function stateIcon(kind) {
    const names = { warning: 'state-warning', critical: 'state-critical', success: 'state-success', info: 'state-info', locked: 'state-locked' };
    return `<div class="state-icon"><img src="/assets/${names[kind] || names.info}.svg" alt=""></div>`;
  }

  function renderShareState(kind, title, message, action = true) {
    $('shareLoading').innerHTML = `${stateIcon(kind)}<h2>${esc(title)}</h2><p>${esc(message)}</p>${action ? '<div class="state-action"><a href="/" class="primary-btn">Back to FileDrop <b>→</b></a></div>' : ''}`;
    $('shareLoading').classList.remove('hidden');
    $('shareCard').classList.add('hidden');
    $('shareLoading').innerHTML = '<div class="spinner"></div><h2>Loading share</h2><p>Checking link status…</p>';
  }

  async function loadShare(id) {
    $('shareLoading').classList.remove('hidden');
    $('shareCard').classList.add('hidden');
    $('shareLoading').innerHTML = '<div class="spinner"></div><h2>Loading share</h2><p>Checking link status…</p>';
    try {
      const response = await fetch(`/api/share/${encodeURIComponent(id)}`, { cache: 'no-store' });
      const meta = await response.json();
      if (!response.ok) throw new Error(meta.error || 'Share not found.');
      $('shareOwnerAvatar').src = meta.owner?.avatar || LOGO;
      $('shareOwnerName').textContent = meta.owner?.name || 'Shared with you';
      $('shareFileName').textContent = meta.originalName;
      $('shareFileInfo').textContent = `${formatBytes(meta.size)} · ${meta.mimetype || 'file'}`;
      $('shareExpires').textContent = meta.expiresAt ? timeLeft(meta.expiresAt) : 'Never';
      $('shareDownloads').textContent = downloadLabel(meta.maxDownloads, meta.downloadsUsed);
      $('shareProtection').textContent = meta.passwordRequired ? 'Password' : 'Open';
      $('shareVirusStatus').textContent = virusLabel(meta.virusCheck);
      $('virusTotalLink').href = meta.sha256 ? `https://www.virustotal.com/gui/file/${encodeURIComponent(meta.sha256)}` : 'https://www.virustotal.com/';
      $('downloadBtn').href = `/api/download/${encodeURIComponent(id)}`;
      $('passwordGate').classList.toggle('hidden', !meta.passwordRequired);
      $('downloadPanel').classList.toggle('hidden', meta.passwordRequired);
      if (meta.riskFlags?.length) { $('shareRisk').textContent = `Caution: ${meta.riskFlags.join(' · ')}`; $('shareRisk').classList.remove('hidden'); }
      else $('shareRisk').classList.add('hidden');
      if (!meta.passwordRequired) $('downloadPanel').classList.remove('hidden');
      $('shareLoading').classList.add('hidden');
      $('shareCard').classList.remove('hidden');
    } catch (err) {
      const message = err?.message || 'This share is not available.';
      const kind = /reached its download limit|no longer available/i.test(message) ? 'warning' : 'critical';
      renderShareState(kind, kind === 'warning' ? 'Share unavailable' : 'File not found', message);
    }
  }

  async function unlockShare() {
    const id = location.pathname.slice(1);
    const password = $('sharePassword').value;
    $('unlockBtn').disabled = true;
    $('passwordError').textContent = '';
    try {
      const response = await fetch(`/api/unlock/${encodeURIComponent(id)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Unable to unlock.');
      $('passwordGate').classList.add('hidden');
      $('downloadPanel').classList.remove('hidden');
      toast('Download unlocked for this session.');
    } catch (err) {
      $('passwordError').textContent = err.message;
    } finally { $('unlockBtn').disabled = false; }
  }

  async function processAvatar(file) {
    if (!file || !/^image\//.test(file.type)) throw new Error('Please choose an image.');
    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.src = url;
      await new Promise((resolve, reject) => { img.onload = resolve; img.onerror = () => reject(new Error('Could not read image.')); });
      const size = 192;
      const canvas = document.createElement('canvas'); canvas.width = size; canvas.height = size;
      const ctx = canvas.getContext('2d');
      const scale = Math.max(size / img.width, size / img.height);
      const w = img.width * scale, h = img.height * scale;
      ctx.drawImage(img, (size - w) / 2, (size - h) / 2, w, h);
      return canvas.toDataURL('image/webp', .82);
    } finally { URL.revokeObjectURL(url); }
  }

  function openFirstVisit(infoOnly = false) {
    const modal = $('firstVisitModal');
    modal.dataset.infoOnly = infoOnly ? '1' : '0';
    $('consentPrivacy').checked = infoOnly || false;
    $('consentTerms').checked = infoOnly || false;
    $('consentGuide').checked = infoOnly || false;
    $('consentPrivacy').disabled = infoOnly;
    $('consentTerms').disabled = infoOnly;
    $('consentGuide').disabled = infoOnly;
    $('acceptFirstVisit').disabled = !infoOnly;
    $('acceptFirstVisit').querySelector('span').textContent = infoOnly ? 'Close' : 'Continue to FileDrop';
    modal.classList.remove('hidden');
  }

  function maybeShowUpdates() {
    if (localStorage.getItem(KEYS.seenVersion) !== APP_VERSION) $('updatesModal').classList.remove('hidden');
  }

  function acceptFirstVisit() {
    if ($('firstVisitModal').dataset.infoOnly === '1') { $('firstVisitModal').classList.add('hidden'); return; }
    if (!($('consentPrivacy').checked && $('consentTerms').checked && $('consentGuide').checked)) return;
    localStorage.setItem(KEYS.consent, String(Date.now()));
    $('firstVisitModal').classList.add('hidden');
    maybeShowUpdates();
    heartbeat();
  }

  function closeUpdates() {
    localStorage.setItem(KEYS.seenVersion, APP_VERSION);
    $('updatesModal').classList.add('hidden');
    heartbeat();
  }

  function applyRetroVisuals() {
    const retro = document.body.classList.contains('retro-mode');
    $('brandLogoImage').src = retro ? '/assets/filedrop-logo-retro.png' : LOGO;
    const heroLogo = document.querySelector('.hero-art img');
    if (heroLogo) heroLogo.src = retro ? '/assets/filedrop-logo-retro.png' : LOGO;
    document.title = retro ? 'FileDrop Classic 2000s' : 'FileDrop — Temporary File Sharing';
    const chrome = $('classicChrome');
    if (chrome) chrome.setAttribute('aria-hidden', retro ? 'false' : 'true');
  }

  function updateClassicClock() {
    const el = $('classicClock');
    if (!el) return;
    el.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function setupEasterEggs() {
    let logoCount = 0, titleCount = 0, logoTimer, titleTimer;
    const retroSaved = localStorage.getItem(RETRO_KEY) === '1';
    const xpSaved = localStorage.getItem(XP_TITLE_KEY) === '1';
    document.body.classList.toggle('retro-mode', retroSaved);
    document.body.classList.toggle('xp-title', xpSaved);

    $('brandLogo').addEventListener('click', e => {
      e.preventDefault();
      logoCount += 1; clearTimeout(logoTimer);
      logoTimer = setTimeout(() => { logoCount = 0; }, 1700);
      if (logoCount >= 4) {
        logoCount = 0;
        const enabled = !document.body.classList.contains('retro-mode');
        document.body.classList.toggle('retro-mode', enabled);
        localStorage.setItem(RETRO_KEY, enabled ? '1' : '0');
        applyRetroVisuals();
        toast(enabled ? 'FileDrop Classic 2000s mode enabled.' : 'Modern mode restored.');
      }
    });

    const titleTargets = [$('heroTitle'), $('brandTitle')].filter(Boolean);
    titleTargets.forEach(target => target.addEventListener('click', e => {
      e.preventDefault();
      e.stopPropagation();
      titleCount += 1; clearTimeout(titleTimer);
      titleTimer = setTimeout(() => { titleCount = 0; }, 1700);
      if (titleCount >= 4) {
        titleCount = 0;
        const enabled = !document.body.classList.contains('xp-title');
        document.body.classList.toggle('xp-title', enabled);
        localStorage.setItem(XP_TITLE_KEY, enabled ? '1' : '0');
        toast(enabled ? 'Classic system font treatment enabled.' : 'Modern title restored.');
      }
    }));
    updateClassicClock();
    setInterval(updateClassicClock, 30000);
  }

  function init() {
    state.profile = getProfile();
    applyProfile();
    $('brandVersion').textContent = APP_VERSION;
    $('profileTrigger').addEventListener('click', () => $('profileMenu').classList.toggle('hidden'));
    document.addEventListener('click', e => { if (!$('profileMenu').contains(e.target) && !$('profileTrigger').contains(e.target)) $('profileMenu').classList.add('hidden'); });
    document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => showView(btn.dataset.view)));

    $('dropzone').addEventListener('click', () => $('fileInput').click());
    $('dropzone').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('fileInput').click(); } });
    ['dragenter','dragover'].forEach(evt => $('dropzone').addEventListener(evt, e => { e.preventDefault(); $('dropzone').classList.add('dragging'); }));
    ['dragleave','drop'].forEach(evt => $('dropzone').addEventListener(evt, e => { e.preventDefault(); $('dropzone').classList.remove('dragging'); }));
    $('dropzone').addEventListener('drop', e => setFile(e.dataTransfer.files?.[0]));
    $('fileInput').addEventListener('change', e => setFile(e.target.files?.[0]));
    $('removeFile').addEventListener('click', clearFile);
    $('uploadBtn').addEventListener('click', uploadFile);
    $('passwordEnabled').addEventListener('change', () => $('passwordWrap').classList.toggle('hidden', !$('passwordEnabled').checked));
    $('downloadsSelect').addEventListener('change', () => $('customDownloadsWrap').classList.toggle('hidden', $('downloadsSelect').value !== 'custom'));
    $('expirySelect').addEventListener('change', () => $('customExpiryWrap').classList.toggle('hidden', $('expirySelect').value !== 'custom'));
    $('defaultExpirySelect').addEventListener('change', () => { state.profile.defaultExpiry = $('defaultExpirySelect').value; setProfile(state.profile); });
    $('defaultDownloadsSelect').addEventListener('change', () => { state.profile.defaultDownloads = $('defaultDownloadsSelect').value; setProfile(state.profile); });
    $('resetSettings').addEventListener('click', resetSettings);

    $('peopleSearch').addEventListener('input', () => { clearTimeout(state.refreshPeopleTimer); state.refreshPeopleTimer = setTimeout(fetchPeople, 250); });
    $('refreshPeople').addEventListener('click', fetchPeople);
    document.addEventListener('keydown', e => { if (e.key === '/' && document.activeElement?.tagName !== 'INPUT') { e.preventDefault(); $('peopleSearch').focus(); } });
    $('confirmDrop').addEventListener('click', confirmDrop);
    $('cancelDrop').addEventListener('click', () => $('dropModal').classList.add('hidden'));
    $('incomingOpen').addEventListener('click', () => { $('incomingBar').classList.add('hidden'); showView('people'); renderInbox(); });
    $('incomingClose').addEventListener('click', () => $('incomingBar').classList.add('hidden'));

    $('clearHistory').addEventListener('click', () => { localStorage.removeItem(KEYS.history); renderHistory(); toast('Local history cleared.'); });
    $('exportHistory').addEventListener('click', () => {
      const data = JSON.stringify(loadJson(KEYS.history, []), null, 2);
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'filedrop-history.json'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 500);
      toast('History exported.');
    });
    $('saveProfile').addEventListener('click', async () => {
      const name = $('profileName').value.trim().replace(/[<>\r\n]/g, '').slice(0, 32);
      if (name.length < 2) { toast('Choose a name with at least 2 characters.'); return; }
      state.profile.nickname = name;
      state.profile.visible = $('profileVisible').checked;
      state.profile.motion = $('motionToggle').checked;
      state.profile.compact = $('compactToggle').checked;
      state.profile.defaultExpiry = $('defaultExpirySelect')?.value || state.profile.defaultExpiry || '3600000';
      state.profile.defaultDownloads = $('defaultDownloadsSelect')?.value || state.profile.defaultDownloads || '5';
      setProfile(state.profile);
      heartbeat();
      toast('Profile saved locally.');
    });
    $('avatarInput').addEventListener('change', async e => {
      try { state.profile.avatar = await processAvatar(e.target.files?.[0]); $('settingsAvatar').src = state.profile.avatar; $('headerAvatar').src = state.profile.avatar; toast('Profile photo ready. Save profile to apply.'); }
      catch (err) { toast(err.message); }
    });
    $('motionToggle').addEventListener('change', () => { state.profile.motion = $('motionToggle').checked; setProfile(state.profile); });
    $('compactToggle').addEventListener('change', () => { state.profile.compact = $('compactToggle').checked; setProfile(state.profile); });
    document.querySelectorAll('.accent-dot').forEach(btn => btn.addEventListener('click', () => { state.profile.accent = btn.dataset.accent; setProfile(state.profile); }));
    $('showUpdates').addEventListener('click', () => { $('updatesModal').classList.remove('hidden'); });
    $('menuPrivacy').addEventListener('click', () => openFirstVisit(true));

    [$('consentPrivacy'), $('consentTerms'), $('consentGuide')].forEach(input => input.addEventListener('change', () => { $('acceptFirstVisit').disabled = !($('consentPrivacy').checked && $('consentTerms').checked && $('consentGuide').checked); }));
    $('acceptFirstVisit').addEventListener('click', acceptFirstVisit);
    $('closeUpdates').addEventListener('click', closeUpdates);
    $('unlockBtn').addEventListener('click', unlockShare);
    $('sharePassword').addEventListener('keydown', e => { if (e.key === 'Enter') unlockShare(); });
    setupEasterEggs();
    applyRetroVisuals();
    if ($('expirySelect')) $('expirySelect').value = state.profile.defaultExpiry || '3600000';
    if ($('downloadsSelect')) $('downloadsSelect').value = state.profile.defaultDownloads || '5';
    if ($('customExpiryWrap')) $('customExpiryWrap').classList.toggle('hidden', $('expirySelect').value !== 'custom');
    if ($('customDownloadsWrap')) $('customDownloadsWrap').classList.toggle('hidden', $('downloadsSelect').value !== 'custom');

    if (!localStorage.getItem(KEYS.consent)) openFirstVisit(false);
    else maybeShowUpdates();
    handleRoute();
    if (localStorage.getItem(KEYS.consent)) heartbeat();
    setInterval(heartbeat, 25000);

    window.addEventListener('popstate', handleRoute);
  }

  window.addEventListener('DOMContentLoaded', init);
})();
