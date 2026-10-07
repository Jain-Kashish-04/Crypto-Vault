/**
 * CryptoVault — compare.js
 * Runs all algorithms on the sample text and renders the comparison table + bar charts.
 */

'use strict';

const PHP_ENDPOINT_CMP = 'php/encrypt.php';

async function runComparison() {
  const text      = document.getElementById('cmpText').value.trim();
  const shift     = parseInt(document.getElementById('cmpShift').value.trim(), 10) || 3;
  const vigKey    = document.getElementById('cmpVigKey').value.trim() || 'SECRET';
  const aesKey    = document.getElementById('cmpAesKey').value.trim();
  const btn       = document.getElementById('cmpRunBtn');

  if (!text) { alert('Please enter some sample text first.'); return; }

  btn.disabled      = true;
  btn.textContent   = '⏳ Running…';

  /* ── Run all JS algorithms ── */
  const results = [];

  function jsRun(label, type, security, reversible, fn) {
    try {
      const t0  = performance.now();
      const out = fn();
      const ms  = performance.now() - t0;
      results.push({ label, type, security, reversible, output: out, length: out.length, ms, error: null });
    } catch (e) {
      results.push({ label, type, security, reversible, output: '', length: 0, ms: 0, error: e.message });
    }
  }

  jsRun('Caesar Cipher',   'Classical', 'Very Low',  true, () => Algorithms.caesarEncrypt(text, shift));
  jsRun('ROT13',           'Classical', 'Very Low',  true, () => Algorithms.rot13(text));
  jsRun('Atbash Cipher',   'Classical', 'Very Low',  true, () => Algorithms.atbash(text));
  jsRun('Vigenère Cipher', 'Classical', 'Low–Medium',true, () => Algorithms.vigenereEncrypt(text, vigKey));
  jsRun('Base64',          'Encoding',  'None',      true, () => Algorithms.base64Encode(text));

  /* ── AES via PHP ── */
  await phpRun('AES-256-CBC', 'Modern', 'Very High', true,  'aes',    aesKey);
  await phpRun('SHA-256 Hash','Modern', 'Very High', false, 'sha256', '');

  async function phpRun(label, type, security, reversible, algo, key) {
    try {
      const t0  = performance.now();
      const res = await fetch(PHP_ENDPOINT_CMP, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algo, mode: 'encrypt', text, key }),
      });
      const json = await res.json();
      const ms   = performance.now() - t0;
      if (json.success) {
        const out = json.data.output;
        results.push({ label, type, security, reversible, output: out, length: out.length, ms: json.data.time_ms ?? ms, error: null });
      } else {
        results.push({ label, type, security, reversible, output: '', length: 0, ms: 0, error: json.error });
      }
    } catch (e) {
      results.push({ label, type, security, reversible, output: '', length: 0, ms: 0, error: 'PHP server not available' });
    }
  }

  /* ── Render table ── */
  renderTable(results);
  renderBarCharts(results);

  document.getElementById('resultsSection').style.display = 'block';
  document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });

  btn.disabled    = false;
  btn.textContent = '▶ Run All';
}

/* ── Security badge helper ── */
function secBadge(sec) {
  const map = {
    'None':       'tag-none',
    'Very Low':   'tag-low',
    'Low–Medium': 'tag-medium',
    'Very High':  'tag-high',
  };
  return `<span class="tag ${map[sec] || 'tag-none'}">${sec}</span>`;
}

function typeBadge(type) {
  const map = {
    'Classical': 'tag-classical',
    'Encoding':  'tag-encoding',
    'Modern':    'tag-modern',
  };
  return `<span class="tag ${map[type] || ''}">${type}</span>`;
}

/* ── Render table ── */
function renderTable(results) {
  const tbody = document.getElementById('cmpTableBody');
  tbody.innerHTML = '';

  results.forEach(r => {
    const tr = document.createElement('tr');

    const outputCell = r.error
      ? `<span style="color:var(--red);font-size:12px;">⚠ ${r.error}</span>`
      : `<span class="output-cell" title="${r.output}">${truncate(r.output, 48)}</span>`;

    const timeCell = r.error ? '—' : `<span class="time-cell">${r.ms < 1 ? '<1ms' : r.ms.toFixed(2) + 'ms'}</span>`;

    tr.innerHTML = `
      <td>${r.label}</td>
      <td class="badge-cell">${typeBadge(r.type)}</td>
      <td class="badge-cell">${secBadge(r.security)}</td>
      <td class="output-cell" style="font-family:var(--font-mono);font-size:12px;color:var(--accent);word-break:break-all;max-width:280px;">${outputCell}</td>
      <td class="len-cell">${r.error ? '—' : r.length + ' chars'}</td>
      <td>${timeCell}</td>
      <td>${r.reversible ? '✅' : '❌ One-way'}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ── Render bar charts ── */
function renderBarCharts(results) {
  const validResults = results.filter(r => !r.error && r.length > 0);

  /* Length chart */
  const maxLen = Math.max(...validResults.map(r => r.length), 1);
  const lenChart = document.getElementById('lenBarChart');
  lenChart.innerHTML = '';
  validResults.forEach(r => {
    const pct = Math.max(4, Math.round((r.length / maxLen) * 100));
    lenChart.innerHTML += `
      <div class="bar-row">
        <div class="bar-label">${r.label}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%"><span>${r.length}</span></div>
        </div>
        <div class="bar-val">${r.length} ch</div>
      </div>`;
  });

  /* Time chart */
  const maxTime = Math.max(...validResults.map(r => r.ms), 0.01);
  const timeChart = document.getElementById('timeBarChart');
  timeChart.innerHTML = '';
  validResults.forEach(r => {
    const pct = Math.max(4, Math.round((r.ms / maxTime) * 100));
    const label = r.ms < 1 ? '<1ms' : r.ms.toFixed(2) + 'ms';
    timeChart.innerHTML += `
      <div class="bar-row">
        <div class="bar-label">${r.label}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%"><span>${label}</span></div>
        </div>
        <div class="bar-val">${label}</div>
      </div>`;
  });
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max) + '…' : str;
}
