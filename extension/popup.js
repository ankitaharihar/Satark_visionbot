const urlInput = document.getElementById('url');
const scanBtn = document.getElementById('scan');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');
const badgeEl = document.getElementById('badge');
const metaEl = document.getElementById('meta');
const reasonsEl = document.getElementById('reasons');

function setStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.style.color = isError ? '#b91c1c' : '#4d6779';
}

function setBadge(verdict) {
  const v = (verdict || 'SAFE').toLowerCase();
  badgeEl.textContent = verdict || 'SAFE';
  badgeEl.className = 'badge';
  if (v === 'phishing') badgeEl.classList.add('phishing');
  else if (v === 'suspicious') badgeEl.classList.add('suspicious');
  else badgeEl.classList.add('safe');
}

async function preloadCurrentTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const current = tabs && tabs[0] ? tabs[0].url : '';
    if (current && /^https?:\/\//i.test(current)) {
      urlInput.value = current;
    }
  } catch (err) {
    setStatus('Tab URL read failed', true);
  }
}

async function scanUrl() {
  const url = urlInput.value.trim();
  if (!/^https?:\/\//i.test(url)) {
    setStatus('Enter valid URL starting with http:// or https://', true);
    return;
  }

  scanBtn.disabled = true;
  setStatus('Analyzing...');
  try {
    const res = await fetch('http://127.0.0.1:8000/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const payload = await res.json();
    if (!res.ok || !payload.ok) {
      throw new Error(payload.error || 'API request failed');
    }

    const data = payload.data || {};
    const model = data.model_result || {};
    setBadge(data.final_verdict);
    metaEl.textContent = `Risk: ${data.final_score || 0}% | Domain: ${data.domain || 'N/A'}`;

    reasonsEl.innerHTML = '';
    const reasonList = (model.reasons && model.reasons.length) ? model.reasons : ['No reasons reported'];
    for (const reason of reasonList.slice(0, 5)) {
      const li = document.createElement('li');
      li.textContent = String(reason);
      reasonsEl.appendChild(li);
    }

    resultEl.style.display = 'block';
    setStatus('Done');
  } catch (err) {
    setStatus(err.message || 'Extension request failed', true);
  } finally {
    scanBtn.disabled = false;
  }
}

scanBtn.addEventListener('click', scanUrl);
preloadCurrentTab();
