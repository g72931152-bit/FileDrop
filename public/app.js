'use strict';

const $ = (id) => document.getElementById(id);
const fileInput = $('fileInput');
const dropzone = $('dropzone');
const fileRow = $('fileRow');
const fileName = $('fileName');
const fileSize = $('fileSize');
const removeFile = $('removeFile');
const uploadButton = $('uploadButton');
const progressWrap = $('progressWrap');
const progressBar = $('progressBar');
const progressValue = $('progressValue');
const progressLabel = $('progressLabel');
const passwordEnabled = $('passwordEnabled');
const passwordWrap = $('passwordWrap');
const passwordInput = $('passwordInput');
const deleteAfterDownload = $('deleteAfterDownload');
const expiresInHour = $('expiresInHour');
const maxDownloads = $('maxDownloads');
const homeView = $('homeView');
const shareView = $('shareView');
const shareState = $('shareState');
const toast = $('toast');

let selectedFile = null;
let toastTimer = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = units[0];
  for (let i = 0; value >= 1024 && i < units.length - 1; i += 1) {
    value /= 1024;
    unit = units[i + 1];
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${unit}`;
}

function formatTimeRemaining(expiresAt) {
  if (!expiresAt) return 'No automatic expiry';
  const diff = Math.max(0, expiresAt - Date.now());
  const minutes = Math.ceil(diff / 60000);
  if (minutes < 60) return `Expires in ${minutes} min`;
  return 'Expires in 1 hour';
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2800);
}

function setFile(file) {
  if (!file) return;
  const max = 2 * 1024 * 1024 * 1024;
  if (file.size > max) {
    showToast('This file is larger than 2 GB.');
    return;
  }
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileRow.classList.remove('hidden');
  dropzone.classList.add('hidden');
  uploadButton.disabled = false;
}

function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  fileRow.classList.add('hidden');
  dropzone.classList.remove('hidden');
  uploadButton.disabled = true;
}

function updatePasswordField() {
  passwordWrap.classList.toggle('hidden', !passwordEnabled.checked);
  passwordInput.required = passwordEnabled.checked;
  if (!passwordEnabled.checked) passwordInput.value = '';
}

function setUploading(isUploading) {
  uploadButton.disabled = isUploading || !selectedFile;
  uploadButton.querySelector('.button-label').textContent = isUploading ? 'Uploading…' : 'Create share link';
  progressWrap.classList.toggle('hidden', !isUploading);
}

async function uploadFile() {
  if (!selectedFile) return;
  if (passwordEnabled.checked && passwordInput.value.length < 4) {
    passwordInput.focus();
    showToast('Enter a password with at least 4 characters.');
    return;
  }

  const form = new FormData();
  form.append('file', selectedFile);
  form.append('settings', JSON.stringify({
    deleteAfterDownload: deleteAfterDownload.checked,
    expiresInHour: expiresInHour.checked,
    passwordEnabled: passwordEnabled.checked,
    password: passwordEnabled.checked ? passwordInput.value : '',
    maxDownloads: Number(maxDownloads.value),
  }));

  setUploading(true);
  progressBar.style.width = '0%';
  progressValue.textContent = '0%';
  progressLabel.textContent = 'Uploading…';

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload');
  xhr.responseType = 'json';
  xhr.upload.onprogress = (event) => {
    if (!event.lengthComputable) return;
    const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
    progressBar.style.width = `${percent}%`;
    progressValue.textContent = `${percent}%`;
    progressLabel.textContent = percent >= 100 ? 'Finalizing…' : 'Uploading…';
  };
  xhr.onerror = () => {
    setUploading(false);
    progressWrap.classList.add('hidden');
    showToast('Connection failed. Please try again.');
  };
  xhr.onload = () => {
    setUploading(false);
    if (xhr.status >= 200 && xhr.status < 300 && xhr.response?.shareUrl) {
      progressBar.style.width = '100%';
      progressValue.textContent = '100%';
      progressLabel.textContent = 'Ready';
      window.history.pushState({}, '', new URL(xhr.response.shareUrl).pathname);
      renderShare(xhr.response.id);
      return;
    }
    progressWrap.classList.add('hidden');
    showToast(xhr.response?.error || 'Upload failed.');
  };
  xhr.send(form);
}

function shareTemplate({ item, passwordError = '' }) {
  const url = `${window.location.origin}/${encodeURIComponent(item.id)}`;
  const remaining = Math.max(0, item.maxDownloads - item.downloadsUsed);
  return `
    <div class="share-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 15.7a3.7 3.7 0 1 0 0-7.4 3.7 3.7 0 0 0 0 7.4Z" stroke="currentColor" stroke-width="1.6"/><path d="M15.1 10.7 19 6.8m0 0v3.1m0-3.1h-3.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </div>
    <div class="share-kicker">Ready to share</div>
    <h1 class="share-title">${escapeHtml(item.originalName)}</h1>
    <div class="share-meta">
      <span class="meta-pill">${formatBytes(item.size)}</span>
      <span class="meta-pill">${remaining} download${remaining === 1 ? '' : 's'} remaining</span>
      <span class="meta-pill">${escapeHtml(formatTimeRemaining(item.expiresAt))}</span>
      ${item.passwordRequired ? '<span class="meta-pill">Password protected</span>' : ''}
    </div>
    <div class="share-box">
      <div class="share-label">Share link</div>
      <div class="link-box">
        <input class="link-input" value="${escapeHtml(url)}" readonly aria-label="Share link">
        <button class="copy-button" type="button" data-action="copy" data-copy="${escapeHtml(url)}">Copy</button>
      </div>
      ${item.passwordRequired ? `
        <div class="password-gate">
          <div class="share-label">Password required</div>
          <input id="sharePassword" type="password" autocomplete="current-password" placeholder="Enter download password">
          ${passwordError ? `<div class="password-error">${escapeHtml(passwordError)}</div>` : ''}
          <button class="download-button" type="button" data-action="unlock">Unlock &amp; download</button>
        </div>
      ` : `
        <button class="download-button" type="button" data-action="download">Download file</button>
      `}
      <div class="share-note">This link is temporary. The service does not require an account and automatically removes expired shares.</div>
    </div>
  `;
}

function errorTemplate(title, message) {
  return `
    <div class="state-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M12 8.3v4.9M12 16.7h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M10.2 4.9 3.6 16.1a2 2 0 0 0 1.73 3h13.34a2 2 0 0 0 1.73-3L13.8 4.9a2 2 0 0 0-3.6 0Z" stroke="currentColor" stroke-width="1.5"/></svg></div>
    <div class="share-kicker">FileDrop</div>
    <div class="state-title">${escapeHtml(title)}</div>
    <p class="state-copy">${escapeHtml(message)}</p>
    <div class="state-action"><button class="secondary-button" type="button" data-action="home">Back to FileDrop</button></div>
  `;
}

async function renderShare(id) {
  homeView.classList.add('hidden');
  shareView.classList.remove('hidden');
  shareState.innerHTML = '<div class="state-copy">Loading share…</div>';
  try {
    const response = await fetch(`/api/share/${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'This link is not available.');
    shareState.innerHTML = shareTemplate({ item: data });
    shareState.classList.remove('reveal');
    void shareState.offsetWidth;
    shareState.classList.add('reveal');
  } catch (error) {
    shareState.innerHTML = errorTemplate('Link unavailable', error.message);
  }
}

function showHome(pushState = false) {
  if (pushState) window.history.pushState({}, '', '/');
  shareView.classList.add('hidden');
  homeView.classList.remove('hidden');
}

async function downloadFile(id) {
  window.location.href = `/api/download/${encodeURIComponent(id)}`;
}

async function unlockAndDownload(id) {
  const input = $('sharePassword');
  const password = input?.value || '';
  if (!password) return;
  const button = document.querySelector('[data-action="unlock"]');
  if (button) { button.disabled = true; button.textContent = 'Checking…'; }
  try {
    const response = await fetch(`/api/unlock/${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Unable to unlock this file.');
    downloadFile(id);
  } catch (error) {
    shareState.innerHTML = shareTemplate({ item: currentShareItem || { id }, passwordError: error.message });
    $('sharePassword')?.focus();
  }
}

let currentShareItem = null;

shareState.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  if (action === 'home') return showHome(true);
  if (action === 'copy') {
    try {
      await navigator.clipboard.writeText(target.dataset.copy);
      target.textContent = 'Copied';
      setTimeout(() => { target.textContent = 'Copy'; }, 1400);
    } catch { showToast('Copy failed.'); }
    return;
  }
  const id = window.location.pathname.slice(1);
  if (action === 'download') return downloadFile(id);
  if (action === 'unlock') return unlockAndDownload(id);
});

async function hydrateShare() {
  const id = window.location.pathname.slice(1);
  if (!id || !/^[A-Za-z0-9]{4,32}$/.test(id)) {
    showHome(false);
    return;
  }
  const response = await fetch(`/api/share/${encodeURIComponent(id)}`).catch(() => null);
  if (!response) return renderShare(id);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) return renderShare(id);
  currentShareItem = data;
  homeView.classList.add('hidden');
  shareView.classList.remove('hidden');
  shareState.innerHTML = shareTemplate({ item: data });
}

fileInput.addEventListener('change', () => setFile(fileInput.files?.[0]));
removeFile.addEventListener('click', (event) => { event.stopPropagation(); clearFile(); });
dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); fileInput.click(); }
});
['dragenter', 'dragover'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
  event.preventDefault(); dropzone.classList.add('dragover');
}));
['dragleave', 'drop'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
  event.preventDefault(); dropzone.classList.remove('dragover');
}));
dropzone.addEventListener('drop', (event) => setFile(event.dataTransfer?.files?.[0]));
passwordEnabled.addEventListener('change', updatePasswordField);
uploadButton.addEventListener('click', uploadFile);
window.addEventListener('popstate', hydrateShare);

updatePasswordField();
hydrateShare();
