/* Feature-flagged, reversible Interface 1 uploader.  The legacy uploader
 * remains in app.js and is used when WA_LARGE_BATCH_UPLOAD_ENABLED is false. */
(() => {
  if (!window.WA_LARGE_BATCH_UPLOAD_ENABLED) return;

  const CHUNK_SIZE = 100;
  const MAX_ATTEMPTS = 3;
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('pcap-file-batch');
  const folderInput = document.getElementById('pcap-folder-batch');
  const browseFiles = document.getElementById('btn-browse-files');
  const browseFolder = document.getElementById('btn-browse-folder');
  const allFilesToggle = document.getElementById('toggle-all-pcap-files');
  const fileList = document.getElementById('upload-file-list');
  const countBadge = document.getElementById('file-count-badge');
  const registerAndFilter = document.getElementById('btn-upload-batch');
  const registerOnly = document.getElementById('btn-register-only');
  const clearButton = document.getElementById('btn-clear-files');
  const statusElement = document.getElementById('upload-status');
  if (!dropZone || !fileInput || !statusElement) return;

  let selectedFiles = [];

  const wait = (ms) => new Promise(resolve => window.setTimeout(resolve, ms));
  const show = (message, type) => window.showStatus(statusElement, message, type);

  function syncAcceptFilter() {
    if (allFilesToggle && allFilesToggle.checked) fileInput.removeAttribute('accept');
    else fileInput.setAttribute('accept', '.pcap,.pcapng,.cap,.dmp,.json,.csv,application/vnd.tcpdump.pcap,application/x-pcapng,application/octet-stream');
  }

  function isValidCaptureFile(file, folderUpload) {
    if (!file || !file.name || file.name.startsWith('.') || file.name === 'Thumbs.db' || file.name === 'desktop.ini') return false;
    if (/\.(wav|wave|mp3|m4a|aac|ogg|flac|mp4|avi|mov|mkv|jpg|jpeg|png|gif|bmp|webp|ico|svg|exe|dll|zip|tar|gz|rar|7z|pdf|docx?|xlsx?|pptx?|txt)$/i.test(file.name)) return false;
    return !folderUpload || /\.(pcap|pcapng|cap|dmp|json|csv)$/i.test(file.name);
  }

  function addFiles(files, folderUpload) {
    const valid = Array.from(files).filter(file => isValidCaptureFile(file, folderUpload));
    if (!valid.length && files.length) {
      window.showToast('No valid capture files were found. Media and document files are excluded.', 'warning');
      return;
    }
    const known = new Set(selectedFiles.map(file => `${file.name}_${file.size}`));
    valid.forEach(file => {
      const key = `${file.name}_${file.size}`;
      if (!known.has(key)) { selectedFiles.push(file); known.add(key); }
    });
    renderFileList();
  }

  function renderFileList() {
    fileList.innerHTML = '';
    // Rendering thousands of rows makes selection needlessly slow.  The full
    // count remains visible and removal still works for the displayed sample.
    selectedFiles.slice(0, 100).forEach((file, index) => {
      const row = document.createElement('div');
      row.className = 'flex items-center justify-between bg-gray-50 border rounded px-3 py-2 text-sm';
      row.innerHTML = `<span class="font-mono truncate">${file.name}</span><span class="text-gray-500 ml-3">${(file.size / 1024).toFixed(1)} KB</span><button type="button" class="text-gray-400 hover:text-red-600 ml-3">&times;</button>`;
      row.querySelector('button').onclick = () => { selectedFiles.splice(index, 1); renderFileList(); };
      fileList.appendChild(row);
    });
    if (selectedFiles.length > 100) {
      const more = document.createElement('div');
      more.className = 'text-xs text-gray-500 px-2';
      more.textContent = `Showing the first 100 of ${selectedFiles.length} selected files.`;
      fileList.appendChild(more);
    }
    countBadge.textContent = selectedFiles.length ? `${selectedFiles.length} file(s) selected` : '';
    countBadge.classList.toggle('hidden', !selectedFiles.length);
    [registerAndFilter, registerOnly, clearButton].forEach(button => {
      if (!button) return;
      button.classList.toggle('hidden', !selectedFiles.length);
      button.classList.toggle('flex', !!selectedFiles.length);
    });
  }

  async function parseResponse(response) {
    const body = await response.text();
    const isJson = (response.headers.get('content-type') || '').toLowerCase().includes('application/json');
    let data = null;
    if (isJson && body) {
      try { data = JSON.parse(body); } catch (_) { /* fall through to a useful error below */ }
    }
    if (!response.ok) {
      const detail = data && data.error ? data.error : `Request failed with HTTP ${response.status}${response.statusText ? ` (${response.statusText})` : ''}.`;
      const error = new Error(detail);
      error.retryable = response.status >= 500;
      throw error;
    }
    if (!data) throw new Error(`The server returned an invalid response (HTTP ${response.status}).`);
    return data;
  }

  async function postChunk(files) {
    let lastError;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      try {
        const form = new FormData();
        files.forEach(file => form.append('pcap_file', file));
        const vantage = document.getElementById('capture-vantage')?.value.trim();
        const subscribers = document.getElementById('subscriber-ips')?.value.trim();
        if (vantage) form.append('capture_vantage', vantage);
        if (subscribers) form.append('subscriber_ips', subscribers);
        return await parseResponse(await fetch('/api/register/batch', {
          method: 'POST', headers: { Accept: 'application/json' }, body: form
        }));
      } catch (error) {
        lastError = error;
        const retryable = error.retryable || error instanceof TypeError;
        if (!retryable || attempt === MAX_ATTEMPTS) throw error;
        await wait(500 * attempt);
      }
    }
    throw lastError;
  }

  async function postJson(url, payload) {
    return parseResponse(await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(payload)
    }));
  }

  async function pollJob(jobId) {
    while (true) {
      const status = await parseResponse(await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, { headers: { Accept: 'application/json' } }));
      show(`Filtering: ${status.progress_pct || 0}% (${status.processed_files || 0}/${status.total_files || 0})`, 'info');
      if (['completed', 'completed_with_errors', 'failed'].includes(status.status)) return status;
      await wait(2000);
    }
  }

  async function registerEvidence(filterAfterRegistration) {
    if (!selectedFiles.length) return;
    const originalFiles = selectedFiles.slice();
    const actionButton = filterAfterRegistration ? registerAndFilter : registerOnly;
    await window.withSpinner(actionButton, async () => {
      const uploadIds = new Set();
      const failures = [];
      for (let offset = 0; offset < originalFiles.length; offset += CHUNK_SIZE) {
        const chunk = originalFiles.slice(offset, offset + CHUNK_SIZE);
        show(`Registering files ${offset + 1}-${offset + chunk.length} of ${originalFiles.length}...`, 'info');
        try {
          const result = await postChunk(chunk);
          (result.receipts || []).forEach(receipt => {
            if (receipt.upload_id && !receipt.error) uploadIds.add(receipt.upload_id);
            else failures.push(`${receipt.filename || 'Unknown file'}: ${receipt.error || 'Registration failed.'}`);
          });
        } catch (error) {
          failures.push(`Files ${offset + 1}-${offset + chunk.length}: ${error.message}`);
        }
      }
      if (!uploadIds.size) {
        show(`No files were registered. ${failures.slice(0, 3).join(' ')}`, 'error');
        return;
      }
      const failureSummary = failures.length ? ` ${failures.length} file or chunk failure(s) were retained for review.` : '';
      if (!filterAfterRegistration) {
        selectedFiles = []; renderFileList();
        show(`${uploadIds.size} of ${originalFiles.length} file(s) registered in RAW_PCAP.${failureSummary}`, failures.length ? 'warning' : 'success');
        window.setTimeout(() => { window.location.href = '/interface/evidence-storage?view=raw'; }, 700);
        return;
      }
      show(`Registered ${uploadIds.size} file(s). Starting asynchronous filtering...${failureSummary}`, failures.length ? 'warning' : 'info');
      const job = await postJson('/api/filter', { upload_ids: [...uploadIds] });
      const finalStatus = await pollJob(job.job_id);
      selectedFiles = []; renderFileList();
      if (finalStatus.status === 'failed') {
        show(`Filtering failed. ${(finalStatus.errors || []).slice(-1)[0] || 'See the job status for details.'}`, 'error');
        return;
      }
      const jobErrors = (finalStatus.errors || []).length;
      show(`Filtering ${jobErrors ? 'completed with errors' : 'completed'}: ${finalStatus.processed_files}/${finalStatus.total_files} file(s).`, jobErrors ? 'warning' : 'success');
      window.setTimeout(() => { window.location.href = `/interface/classification?job_id=${encodeURIComponent(job.job_id)}`; }, 700);
    });
  }

  browseFiles && browseFiles.addEventListener('click', event => { event.stopPropagation(); syncAcceptFilter(); fileInput.click(); });
  browseFolder && folderInput && browseFolder.addEventListener('click', event => { event.stopPropagation(); folderInput.click(); });
  dropZone.addEventListener('click', event => { if (!event.target.closest('button') && !event.target.closest('input')) { syncAcceptFilter(); fileInput.click(); } });
  fileInput.addEventListener('change', event => { if (event.target.files.length) addFiles(event.target.files, false); fileInput.value = ''; });
  folderInput && folderInput.addEventListener('change', event => {
    const files = Array.from(event.target.files || []).filter(file => !file.webkitRelativePath || file.webkitRelativePath.split('/').length <= 2);
    if (files.length) addFiles(files, true);
    folderInput.value = '';
  });
  dropZone.addEventListener('dragover', event => { event.preventDefault(); dropZone.classList.add('border-blue-500', 'bg-blue-50/50'); });
  dropZone.addEventListener('dragleave', event => { event.preventDefault(); dropZone.classList.remove('border-blue-500', 'bg-blue-50/50'); });
  dropZone.addEventListener('drop', event => { event.preventDefault(); dropZone.classList.remove('border-blue-500', 'bg-blue-50/50'); addFiles(event.dataTransfer.files || [], false); });
  clearButton && clearButton.addEventListener('click', () => { selectedFiles = []; renderFileList(); });
  registerAndFilter && registerAndFilter.addEventListener('click', () => registerEvidence(true));
  registerOnly && registerOnly.addEventListener('click', () => registerEvidence(false));
})();
