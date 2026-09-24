'use strict';

/* ================================================================
   app.js â€” Sidebar state & AJAX helpers for forensic analyzer UI
   No frameworks. Vanilla JS only.
   ================================================================ */

// Switch to a different case: preserve current interface path
function switchCase(batchId) {
  if (!batchId) return;
  const url = new URL(window.location.href);
  url.searchParams.set('batch_id', batchId);
  window.location.href = url.toString();
}

// Toast notification system
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) {
    window.alert(message); // Fallback
    return;
  }
  const toast = document.createElement('div');
  
  let bgClass, iconClass;
  if (type === 'error') {
    bgClass = 'bg-red-500'; iconClass = 'fa-circle-xmark';
  } else if (type === 'success') {
    bgClass = 'bg-green-500'; iconClass = 'fa-circle-check';
  } else if (type === 'warning') {
    bgClass = 'bg-yellow-500'; iconClass = 'fa-triangle-exclamation';
  } else {
    bgClass = 'bg-blue-500'; iconClass = 'fa-circle-info';
  }
  
  toast.className = `${bgClass} text-white px-4 py-3 rounded shadow-lg flex items-center transform transition-all duration-300 translate-y-full opacity-0 max-w-sm`;
  toast.innerHTML = `<i class="fa-solid ${iconClass} mr-3 text-lg"></i><span class="text-sm font-medium leading-tight">${message}</span>`;
  
  container.appendChild(toast);
  
  // Animate in
  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-full', 'opacity-0');
  });
  
  // Auto-remove
  setTimeout(() => {
    toast.classList.add('opacity-0');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 4000);
}

// Table search filter
function filterTable(query, tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const rows = table.querySelectorAll('tbody tr');
  const q = query.toLowerCase();
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// Animate the filter progress bar (Tailwind-compatible)
function animateProgress(pct) {
  const bar = document.getElementById('filter-progress');
  if (!bar) return;
  bar.classList.remove('hidden');
  // Target the inner fill div (first child)
  const fill = bar.querySelector('div');
  if (fill) fill.style.width = pct + '%';
}

// Generic JSON fetch helper
async function apiFetch(url, options = {}) {
  const defaults = {
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
  };
  const res = await fetch(url, { ...defaults, ...options });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

// Show/hide FA spinner on a button while an async operation runs
async function withSpinner(btn, fn) {
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i>Running...';
  try {
    await fn();
  } finally {
    btn.innerHTML = orig;
    btn.disabled = false;
  }
}

// Helper: show a Tailwind-styled status message
function showStatus(el, message, type = 'info') {
  if (!el) return;
  const styles = {
    info:    'bg-blue-50 border-l-4 border-blue-500 text-blue-800 p-3 rounded-md text-sm',
    success: 'bg-green-50 border-l-4 border-green-500 text-green-800 p-3 rounded-md text-sm',
    warning: 'bg-yellow-50 border-l-4 border-yellow-500 text-yellow-800 p-3 rounded-md text-sm',
    error:   'bg-red-50 border-l-4 border-red-500 text-red-800 p-3 rounded-md text-sm',
  };
  el.className = styles[type] || styles.info;
  el.textContent = message;
  el.classList.remove('hidden');
}

// â”€â”€ Deletion Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function deleteBatch(batchId) {
  if (!confirm('Delete this entire case and all associated files? This cannot be undone.')) return;
  try {
    await apiFetch(`/api/delete/batch/${batchId}`, { method: 'POST' });
    window.location.href = '/';
  } catch (e) {
    showToast('Error: ' + e.message, 'warning');
  }
}

async function deleteUpload(uploadId) {
  if (!confirm('Delete this PCAP file?')) return;
  try {
    await apiFetch(`/api/delete/upload/${uploadId}`, { method: 'POST' });
    window.location.reload();
  } catch (e) {
    showToast('Error: ' + e.message, 'warning');
  }
}

// â”€â”€ Interface 1: Drag & Drop File Upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ Interface 1: Drag & Drop and Multi-mode Upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('pcap-file-batch');
const folderInput = document.getElementById('pcap-folder-batch');
const btnBrowseFiles = document.getElementById('btn-browse-files');
const btnBrowseFolder = document.getElementById('btn-browse-folder');
const toggleAllPcap = document.getElementById('toggle-all-pcap-files');
const fileList = document.getElementById('upload-file-list');
const fileCountBadge = document.getElementById('file-count-badge');
const btnUploadBatch = document.getElementById('btn-upload-batch');
const btnClearFiles = document.getElementById('btn-clear-files');
const btnRegisterOnly = document.getElementById('btn-register-only');
let selectedFiles = [];

if (dropZone && fileInput && !window.WA_LARGE_BATCH_UPLOAD_ENABLED) {
  // Sync accept attribute based on toggle
  function syncAcceptFilter() {
    if (!fileInput) return;
    if (toggleAllPcap && toggleAllPcap.checked) {
      // Show ALL files in Windows file dialog without Wireshark restriction
      fileInput.removeAttribute('accept');
    } else {
      // Restrict to capture file extensions + MIME types
      fileInput.setAttribute('accept', '.pcap,.pcapng,.cap,.dmp,.json,.csv,application/vnd.tcpdump.pcap,application/x-pcapng,application/octet-stream');
    }
  }
  
  if (toggleAllPcap) {
    syncAcceptFilter();
    toggleAllPcap.addEventListener('change', syncAcceptFilter);
  }

  // Browse Files button
  if (btnBrowseFiles) {
    btnBrowseFiles.addEventListener('click', (e) => {
      e.stopPropagation();
      syncAcceptFilter();
      fileInput.click();
    });
  }

  // Browse Folder button
  if (btnBrowseFolder && folderInput) {
    btnBrowseFolder.addEventListener('click', (e) => {
      e.stopPropagation();
      folderInput.click();
    });
  }

  // Clicking empty dropzone area triggers file picker
  dropZone.addEventListener('click', (e) => {
    if (e.target.closest('button') || e.target.closest('input')) return;
    syncAcceptFilter();
    fileInput.click();
  });

  // Filter helper: check if file is a valid capture file
  function isValidCaptureFile(file, isFolderUpload = false) {
    if (!file || !file.name) return false;
    const name = file.name;
    // Skip OS hidden / metadata files
    if (name.startsWith('.') || name === 'Thumbs.db' || name === 'desktop.ini') return false;
    
    // Explicitly reject media and non-packet files (WAV, MP3, video, images, binaries)
    const nonCaptureExtensions = /\.(wav|wave|mp3|m4a|aac|ogg|flac|mp4|avi|mov|mkv|jpg|jpeg|png|gif|bmp|webp|ico|svg|exe|dll|zip|tar|gz|rar|7z|pdf|docx?|xlsx?|pptx?|txt)$/i;
    if (nonCaptureExtensions.test(name)) return false;

    // For folder crawling: strictly only accept capture formats
    if (isFolderUpload) {
      return /\.(pcap|pcapng|cap|dmp|json|csv)$/i.test(name);
    }

    // If "ALL pcap files" is checked for manual file selection, accept any file except rejected media/binaries
    if (toggleAllPcap && toggleAllPcap.checked) return true;

    // Otherwise check for known capture extensions
    return /\.(pcap|pcapng|cap|dmp|json|csv)$/i.test(name);
  }

  function addFiles(newFiles, isFolderUpload = false) {
    const valid = Array.from(newFiles).filter(f => isValidCaptureFile(f, isFolderUpload));
    if (valid.length === 0 && newFiles.length > 0) {
      showToast('No valid capture files (.pcap, .pcapng, .cap, .dmp, .json, .csv) found. Media files (.wav, .mp3, etc.) are excluded.', 'warning');
      return;
    }
    // Deduplicate by name and size
    const existingKeys = new Set(selectedFiles.map(f => `${f.name}_${f.size}`));
    for (const f of valid) {
      const key = `${f.name}_${f.size}`;
      if (!existingKeys.has(key)) {
        selectedFiles.push(f);
        existingKeys.add(key);
      }
    }
    renderFileList();
  }

  // File input change
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      addFiles(e.target.files, false);
      fileInput.value = '';
    }
  });

  // Folder input change (crawl top-level files in selected folder)
  if (folderInput) {
    folderInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        // User requested: "it can crawl the top level files within selected folder"
        const files = Array.from(e.target.files).filter(f => {
          if (!f.webkitRelativePath) return true;
          // webkitRelativePath: "folderName/fileName.pcap" has 2 segments (split by / has length <= 2)
          const parts = f.webkitRelativePath.split('/');
          return parts.length <= 2;
        });
        addFiles(files, true);
        folderInput.value = '';
      }
    });
  }

  function renderFileList() {
    if (!fileList) return; fileList.innerHTML = '';
    selectedFiles.forEach((file, index) => { const row=document.createElement('div'); row.className='flex items-center justify-between bg-gray-50 border rounded px-3 py-2 text-sm'; row.innerHTML=`<span class="font-mono">${file.name}</span><span class="text-gray-500">${(file.size/1024).toFixed(1)} KB</span><button type="button" class="text-gray-400 hover:text-red-600">&times;</button>`; row.querySelector('button').onclick=()=>{selectedFiles.splice(index,1);renderFileList()}; fileList.appendChild(row); });
    if (fileCountBadge) { fileCountBadge.textContent=selectedFiles.length?`${selectedFiles.length} file(s) selected`:''; fileCountBadge.classList.toggle('hidden',!selectedFiles.length); }
    [btnUploadBatch,btnRegisterOnly,btnClearFiles].forEach(button=>{if(button){button.classList.toggle('hidden',!selectedFiles.length);button.classList.toggle('flex',!!selectedFiles.length)}});
  }
  dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('border-blue-500','bg-blue-50/50')});
  dropZone.addEventListener('dragleave',e=>{e.preventDefault();dropZone.classList.remove('border-blue-500','bg-blue-50/50')});
  dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('border-blue-500','bg-blue-50/50');addFiles(Array.from(e.dataTransfer.files||[]),false)});
  if(btnClearFiles) btnClearFiles.addEventListener('click',()=>{selectedFiles=[];renderFileList()});
  async function registerEvidence(filterAfterRegistration){
    if(!selectedFiles.length)return; const statusEl=document.getElementById('upload-status'), actionButton=filterAfterRegistration?btnUploadBatch:btnRegisterOnly;
    await withSpinner(actionButton,async()=>{const formData=new FormData();selectedFiles.forEach(file=>formData.append('pcap_file',file));try{const response=await fetch('/api/register/batch',{method:'POST',body:formData}),data=await response.json();if(!response.ok)throw new Error(data.error||'Registration failed.');const receipts=data.receipts||[],failures=receipts.filter(item=>item.error),ids=receipts.filter(item=>item.upload_id&&!item.error).map(item=>item.upload_id);if(!ids.length){showStatus(statusEl,`No files were registered. ${failures.map(item=>item.filename+': '+item.error).join(' ')}`,'error');return}if(!filterAfterRegistration){selectedFiles=[];renderFileList();showStatus(statusEl,`${ids.length} file(s) registered in RAW_PCAP.`,'success');setTimeout(()=>window.location.href='/interface/evidence-storage?view=raw',500);return}showStatus(statusEl,`Registered ${ids.length} file(s). Filtering complete captures...`,'info');const filterResponse=await fetch('/api/filter',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({upload_ids:ids})}),filtered=await filterResponse.json();if(!filterResponse.ok)throw new Error(filtered.error||'Filtering failed.');selectedFiles=[];renderFileList();const created=(filtered.outcomes||[]).filter(item=>item.status==='filtered_output_created').length,unmatched=(filtered.outcomes||[]).filter(item=>item.status==='no_whatsapp_match').length;showStatus(statusEl,`Filtering complete: ${created} filtered output(s), ${unmatched} no-match file(s). Opening results...`,created?'success':'warning');setTimeout(()=>window.location.href=`/interface/classification?upload_ids=${encodeURIComponent(ids.join(','))}`,650)}catch(error){showStatus(statusEl,'Error: '+error.message,'error')}});
  }
  btnUploadBatch.addEventListener('click',()=>registerEvidence(true)); if(btnRegisterOnly)btnRegisterOnly.addEventListener('click',()=>registerEvidence(false));
}
const analyzeBtn = document.getElementById('btn-run-analyze-case');
if (analyzeBtn) {
  analyzeBtn.addEventListener('click', async () => {
    const batchId = analyzeBtn.dataset.batchId;
    const statusEl = document.getElementById('analyze-status');

    await withSpinner(analyzeBtn, async () => {
      showStatus(statusEl, 'Grouping parties and geolocating across all case files...', 'info');

      try {
        await apiFetch(`/api/analyze${window.location.search}`, { method: 'POST' });
        showStatus(statusEl, 'Analysis complete. Reloadingâ€¦', 'success');
        setTimeout(() => window.location.reload(), 800);
      } catch (e) {
        showStatus(statusEl, 'Error: ' + e.message, 'error');
      }
    });
  });
}

// â”€â”€ Interface 4: Deep Analysis & Compare â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// DEEP_ANALYSIS_DISABLED
/*
const runDeepBtn = document.getElementById('btn-run-deep-case');
if (runDeepBtn) {
  runDeepBtn.addEventListener('click', async () => {
    const batchId = runDeepBtn.dataset.batchId;
    const statusEl = document.getElementById('deep-status');

    await withSpinner(runDeepBtn, async () => {
      showStatus(statusEl, 'Extracting timelines...', 'info');

      try {
        await apiFetch(`/api/deep_analyze/${batchId}`, { method: 'POST' });
        showStatus(statusEl, 'Timeline extraction complete. Reloadingâ€¦', 'success');
        setTimeout(() => window.location.reload(), 800);
      } catch (e) {
        showStatus(statusEl, 'Error: ' + e.message, 'error');
      }
    });
  });
}

const compareBtn = document.getElementById('btn-run-compare-case');
if (compareBtn) {
  compareBtn.addEventListener('click', async () => {
    const batchIdA = compareBtn.dataset.batchId;
    const compareSelect = document.getElementById('compare-select');
    const batchIdB = compareSelect.value;

    if (!batchIdB) {
      showToast('Please select a case to compare with.', 'warning');
      return;
    }

    await withSpinner(compareBtn, async () => {
      try {
        const data = await apiFetch(`/api/compare/${batchIdA}/${batchIdB}`);

        const resultsDiv = document.getElementById('compare-results');
        const scoreSpan = document.getElementById('compare-score');
        const detailsSpan = document.getElementById('compare-details');

        resultsDiv.classList.remove('hidden');
        scoreSpan.textContent = data.score.toFixed(1) + '%';

        const scoreColors = {
          high:   'bg-green-100 text-green-800',
          medium: 'bg-yellow-100 text-yellow-800',
          low:    'bg-red-100 text-red-800',
        };
        const tier = data.score > 50 ? 'high' : data.score > 0 ? 'medium' : 'low';
        scoreSpan.className = `px-3 py-1 rounded-full text-sm font-bold ${scoreColors[tier]}`;

        detailsSpan.textContent = data.details;
      } catch (e) {
        showToast('Error during comparison: ' + e.message, 'warning');
      }
    });
  });
}
*/

// â”€â”€ Interface 2: Forensic Packet Browser Controller â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

(function initForensicPacketBrowser() {
  const root = document.getElementById('forensic-browser-root');
  if (!root) return;
  let view = root.dataset.view === 'file' ? 'file' : 'all';
  let selectedUploadId = root.dataset.uploadId || null;
  let currentPage = 1, perPage = 100, query = '', confidence = 'all', protocol = 'all', selectedPacketId = null, totalPages = 1;
  const $ = (id) => document.getElementById(id);
  const fileItems = [...root.querySelectorAll('.file-item')], tbody = $('packets-tbody');
  const fmt = (v) => v == null ? '-' : new Intl.DateTimeFormat('en-IN',{timeZone:'Asia/Kolkata',day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(Number(v)*1000)) + ' IST';
  const label = (value) => ({
    voice_call: 'Voice Call',
    video_call: 'Video Call',
    call_stream_unresolved: 'Encrypted Call (Unanchored)',
    call_signaling: 'Call Signaling',
    media_transfer: 'Media Attachment',
    photo: 'Photo',
    audio: 'Audio / Voice Note',
    video: 'Video',
    message: 'Text Message',
    dns: 'DNS',
    xmpp_multiplex: 'Chat / Call Signal',
    unclassified: 'Unclassified',
    call_media_candidate: 'Call Stream'
  })[value] || (value || 'Unclassified').replace(/_/g, ' ');
  const range = () => { const p=new URLSearchParams(location.search); return {from:p.get('capture_from'),to:p.get('capture_to')}; };
  function url(path) { const u=new URL(path, location.origin), r=range(), jobId=new URLSearchParams(location.search).get('job_id'); if(r.from)u.searchParams.set('capture_from',r.from); if(r.to)u.searchParams.set('capture_to',r.to); if(jobId)u.searchParams.set('job_id',jobId); return u; }
  function persist() { const u=new URL(location.href); u.searchParams.set('view',view); if(view==='file'&&selectedUploadId)u.searchParams.set('upload_id',selectedUploadId); else u.searchParams.delete('upload_id'); if(query)u.searchParams.set('q',query);else u.searchParams.delete('q'); if(confidence!=='all')u.searchParams.set('confidence',confidence);else u.searchParams.delete('confidence'); if(protocol!=='all')u.searchParams.set('protocol',protocol);else u.searchParams.delete('protocol'); u.searchParams.set('page',currentPage); if(selectedPacketId)u.searchParams.set('packet',selectedPacketId);else u.searchParams.delete('packet'); history.replaceState(null,'',u); }
  function setActive() { fileItems.forEach(x=>x.classList.toggle('is-active',x.dataset.view===view && (view==='all'||x.dataset.uploadId===selectedUploadId))); }
  function resetDetail() { $('detail-empty-state').classList.remove('hidden'); $('detail-active-content').classList.add('hidden'); $('detail-error').classList.add('hidden'); }
  function showDetailError(message) { $('detail-empty-state').classList.add('hidden'); $('detail-active-content').classList.add('hidden'); $('detail-error').textContent=message; $('detail-error').classList.remove('hidden'); }
  function badge(conf) { const c=(conf||'low').toLowerCase(), cls=c==='high'?'bg-green-100 text-green-700':c==='medium'?'bg-amber-100 text-amber-700':'bg-gray-100 text-gray-700'; return `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${cls}">${c.toUpperCase()}</span>`; }
  function proto(p) { const tcp=(p||'').toUpperCase()==='TCP'; return `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${tcp?'bg-blue-50 text-blue-600':'bg-emerald-50 text-emerald-700'}">${p||'-'}</span>`; }
  async function loadDetail(id) { selectedPacketId=id; persist(); const u=url(`/api/packets/detail/${id}`); if(view==='file')u.searchParams.set('upload_id',selectedUploadId); try { const data=await apiFetch(u); const p=data.packet, v=data.verdict; $('detail-error').classList.add('hidden'); $('detail-empty-state').classList.add('hidden'); $('detail-active-content').classList.remove('hidden'); $('detail-packet-no-tag').textContent='#'+p.packet_no; $('detail-pkt-header').textContent='Packet #'+p.packet_no; $('detail-pkt-time').textContent=fmt(p.timestamp); $('detail-pkt-len').textContent=(p.length||0)+' bytes'; $('detail-pkt-ttl').textContent=p.ip_ttl ?? '-'; $('detail-pkt-proto').textContent=p.protocol||'-'; $('detail-pkt-port').textContent=p.dst_port||p.src_port||'-'; $('detail-flow-id').textContent=p.flow_id||'unassigned'; $('detail-src-endpoint').textContent=`${p.src_ip||'-'}:${p.src_port||''}`; $('detail-dst-endpoint').textContent=`${p.dst_ip||'-'}:${p.dst_port||''}`; $('detail-verdict-class').textContent=label(v.media_guess); $('detail-verdict-conf').innerHTML=badge(v.confidence); $('detail-verdict-subactivity').textContent='Activity: '+label(v.sub_activity||'generic')+(v.is_stun?' · STUN validated':''); $('detail-evidence-count').textContent=(data.evidence||[]).length+' corroborating signals'; $('detail-evidence-list').innerHTML=(data.evidence||[]).map(e=>`<div class="p-2 rounded border bg-gray-50 text-[11px]"><div class="font-medium">${e.label} <span class="float-right">${e.strength}</span></div><div class="text-gray-600 mt-1">${e.explanation}</div></div>`).join('')||'<div class="text-xs text-gray-400">No corroborating signals.</div>'; $('detail-exclusions-list').innerHTML=(data.exclusions||[]).map(e=>`<div class="p-2 rounded border border-red-100 bg-red-50 text-[11px]"><b>Not: ${e.target}</b><div class="text-gray-600 mt-1">${e.reason}</div></div>`).join('')||'<div class="text-xs text-gray-400">No exclusion reasoning.</div>'; $('detail-summary-narrative').textContent=data.summary_narrative||'No narrative available.'; } catch(e) { showDetailError('Packet details are unavailable. The evidence may have been removed or is outside the active capture range.'); } }
  async function loadPackets() { const u=url('/api/packets/list'); u.searchParams.set('view',view); if(view==='file')u.searchParams.set('upload_id',selectedUploadId); u.searchParams.set('page',currentPage);u.searchParams.set('per_page',perPage);if(query)u.searchParams.set('q',query);if(confidence!=='all')u.searchParams.set('confidence',confidence);if(protocol!=='all')u.searchParams.set('protocol',protocol); tbody.innerHTML='<tr><td colspan="9" class="p-8 text-center text-gray-400">Loading filtered packets...</td></tr>'; try { const data=await apiFetch(u); totalPages=data.pages||1; currentPage=data.page||1; const stats=data.file_stats||{}, sel=data.selection||{}; $('current-file-title').textContent=sel.filename||'All Filtered Evidence'; $('current-file-subtitle').textContent=`${stats.total_packets||0} filtered packets in selected IST range`; $('stat-pill-total').innerHTML=`Pkts: <b>${stats.total_packets||0}</b>`; $('stat-pill-ips').innerHTML=`Unique IPs: <b>${stats.unique_ips||0}</b>`; $('stat-pill-udp').innerHTML=`UDP: <b>${stats.udp_count||0}</b>`; $('stat-pill-tcp').innerHTML=`TCP: <b>${stats.tcp_count||0}</b>`; const total=data.total||0, first=total?(currentPage-1)*perPage+1:0; $('pagination-info').textContent=`${first}-${Math.min(currentPage*perPage,total)} of ${total}`; $('btn-page-prev').disabled=currentPage<=1;$('btn-page-next').disabled=currentPage>=totalPages;$('footer-status-text').textContent=`Showing ${(data.rows||[]).length} filtered packets. Select a row for forensic details.`; tbody.innerHTML=''; (data.rows||[]).forEach((p, idx)=>{const tr=document.createElement('tr');tr.dataset.packetId=String(p.id);tr.className='cursor-pointer hover:bg-blue-50 border-b';tr.innerHTML=`<td class="p-3">${(currentPage - 1) * perPage + idx + 1}</td><td class="p-3 packet-time">${fmt(p.timestamp)}</td><td class="p-3 font-mono">${p.src_ip||'-'}</td><td class="p-3 font-mono">${p.dst_ip||'-'}</td><td class="p-3">${p.dst_port||p.src_port||'-'}</td><td class="p-3">${proto(p.protocol)}</td><td class="p-3">${p.length||0}</td><td class="p-3">${label(p.whatsapp_media_guess||p.sub_activity)}</td><td class="p-3">${badge(p.whatsapp_confidence)}</td>`;tr.onclick=()=>{tbody.querySelectorAll('tr').forEach(r=>r.classList.remove('bg-blue-100'));tr.classList.add('bg-blue-100');loadDetail(p.id)};tbody.appendChild(tr);}); const wanted=new URLSearchParams(location.search).get('packet'); const target=(data.rows||[]).find(x=>String(x.id)===wanted)||(data.rows||[])[0]; if(target){ const row=[...tbody.querySelectorAll('tr')].find(x=>x.dataset.packetId===String(target.id)); if(row)row.classList.add('bg-blue-100'); loadDetail(target.id); } else { resetDetail(); tbody.innerHTML='<tr><td colspan="9" class="p-8 text-center text-gray-400">No filtered packets match the current criteria.</td></tr>'; } persist(); } catch(e) { tbody.innerHTML=`<tr><td colspan="9" class="p-8 text-center text-red-600">${e.message}</td></tr>`; resetDetail(); } }
  fileItems.forEach(item=>item.onclick=()=>{view=item.dataset.view;selectedUploadId=view==='file'?item.dataset.uploadId:null;currentPage=1;selectedPacketId=null;setActive();resetDetail();loadPackets();}); $('file-search-input').oninput=e=>fileItems.forEach(item=>{if(item.dataset.view==='all')return;item.style.display=(item.textContent||'').toLowerCase().includes(e.target.value.toLowerCase())?'':'none'}); let timer; $('packet-search-input').oninput=e=>{clearTimeout(timer);timer=setTimeout(()=>{query=e.target.value.trim();currentPage=1;loadPackets()},250)}; $('packet-conf-filter').onchange=e=>{confidence=e.target.value;currentPage=1;loadPackets()}; $('packet-proto-filter').onchange=e=>{protocol=e.target.value;currentPage=1;loadPackets()}; $('per-page-select').onchange=e=>{perPage=Number(e.target.value);currentPage=1;loadPackets()}; $('btn-page-prev').onclick=()=>{if(currentPage>1){currentPage--;loadPackets()}}; $('btn-page-next').onclick=()=>{if(currentPage<totalPages){currentPage++;loadPackets()}}; setActive(); loadPackets();
})();
