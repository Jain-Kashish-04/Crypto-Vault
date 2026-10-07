/**
 * CryptoVault — app.js
 * UI controller: algorithm selection, mode toggling, dispatching
 * encrypt/decrypt to JS algorithms or PHP backend, stats, copy, download.
 */

'use strict';

/* ══════════════════════════════════════════════════════════════
   STATE
   ══════════════════════════════════════════════════════════════ */
let currentAlgo = 'caesar';
let currentMode = 'encrypt';
let encryptCount = 0;
let decryptCount = 0;

/* PHP backend endpoint — works when served via a local PHP server */
const PHP_ENDPOINT = 'php/encrypt.php';

/* History API endpoint */
const HISTORY_ENDPOINT = 'php/history.php';

/* ══════════════════════════════════════════════════════════════
   ALGORITHM METADATA
   ══════════════════════════════════════════════════════════════ */
const ALGO_META = {
  caesar: {
    label:    'Caesar Cipher',
    type:     'Classical',
    backend:  'js',
    keyField: 'shift',
    info: {
      title: 'Caesar Cipher — How it works',
      body: `
        <p>The Caesar cipher is one of the simplest encryption techniques. Every letter in the plaintext is shifted a fixed number of positions down the alphabet.</p>
        <p><strong>Example (shift 3):</strong> "HELLO" → "KHOOR" &nbsp;|&nbsp; "WORLD" → "ZRUOG"</p>
        <p><strong>Key:</strong> A number from 1 to 25 representing the shift amount.</p>
        <p><strong>Security:</strong> Very weak — only 25 possible keys. Easily broken by brute force or frequency analysis. Suitable for educational purposes only.</p>
        <p><strong>History:</strong> Used by Julius Caesar to communicate with his generals around 58 BC.</p>
      `
    }
  },
  rot13: {
    label:    'ROT13',
    type:     'Classical',
    backend:  'js',
    keyField: null,
    info: {
      title: 'ROT13 — How it works',
      body: `
        <p>ROT13 is a special case of the Caesar cipher with a fixed shift of 13. Because the English alphabet has 26 letters, applying ROT13 twice returns the original text — making encryption and decryption identical operations.</p>
        <p><strong>Example:</strong> "HELLO" → "URYYB" &nbsp;|&nbsp; "URYYB" → "HELLO"</p>
        <p><strong>Key:</strong> No key required — shift is always 13.</p>
        <p><strong>Security:</strong> None. Purely for obfuscation (e.g. hiding spoilers in online forums). Do not use for sensitive data.</p>
      `
    }
  },
  atbash: {
    label:    'Atbash Cipher',
    type:     'Classical',
    backend:  'js',
    keyField: null,
    info: {
      title: 'Atbash Cipher — How it works',
      body: `
        <p>Atbash is a monoalphabetic substitution cipher where each letter is replaced by the letter that mirrors it in the alphabet: A↔Z, B↔Y, C↔X, and so on. Like ROT13, encryption and decryption are the same operation.</p>
        <p><strong>Example:</strong> "HELLO" → "SVOOL"</p>
        <p><strong>Key:</strong> No key required — the mapping is fixed.</p>
        <p><strong>Security:</strong> Extremely weak. Originally used in the Hebrew alphabet for the Book of Jeremiah. Educational use only.</p>
      `
    }
  },
  vigenere: {
    label:    'Vigenère Cipher',
    type:     'Classical',
    backend:  'js',
    keyField: 'vigenere',
    info: {
      title: 'Vigenère Cipher — How it works',
      body: `
        <p>The Vigenère cipher is a polyalphabetic substitution cipher that uses a repeating keyword to determine the shift for each character. Each letter of the keyword corresponds to a different Caesar shift.</p>
        <p><strong>Example (key "KEY"):</strong> "HELLO" → each letter shifted by K(10), E(4), Y(24), K(10), E(4).</p>
        <p><strong>Key:</strong> A word or phrase (letters only). Longer keys are harder to crack.</p>
        <p><strong>Security:</strong> Much stronger than Caesar but still vulnerable to the Kasiski examination if the key is short. Considered unbreakable for centuries.</p>
      `
    }
  },
  base64: {
    label:    'Base64',
    type:     'Encoding',
    backend:  'js',
    keyField: null,
    info: {
      title: 'Base64 — How it works',
      body: `
        <p><strong>Important:</strong> Base64 is an <em>encoding scheme</em>, not encryption. It converts binary data to an ASCII string using 64 printable characters. Anyone can decode it instantly — there is no secret key.</p>
        <p><strong>Example:</strong> "Hello" → "SGVsbG8="</p>
        <p><strong>Use cases:</strong> Embedding images in HTML/CSS, transmitting data in URLs, email attachments (MIME), JSON payloads.</p>
        <p><strong>Security:</strong> Zero. Do not rely on Base64 for security. Use it for encoding only.</p>
      `
    }
  },
  aes: {
    label:    'AES-256-CBC',
    type:     'Modern',
    backend:  'php',
    keyField: 'aes',
    info: {
      title: 'AES-256-CBC — How it works',
      body: `
        <p>AES (Advanced Encryption Standard) with a 256-bit key in CBC (Cipher Block Chaining) mode is the industry standard for symmetric encryption. It processes data in 128-bit blocks, and each block's ciphertext depends on the previous block.</p>
        <p><strong>Key derivation:</strong> Your passphrase is hashed with SHA-256 to produce a 256-bit key. A random IV (Initialisation Vector) is generated for each encryption to ensure identical plaintexts produce different ciphertexts.</p>
        <p><strong>Security:</strong> Extremely high. AES-256 has never been practically broken. Used by governments, banks, and security software worldwide.</p>
        <p><strong>Note:</strong> Requires a PHP server to run. If running as a static file, this algorithm will be unavailable.</p>
      `
    }
  },
  sha256: {
    label:    'SHA-256 Hash',
    type:     'Modern',
    backend:  'php',
    keyField: null,
    decryptDisabled: true,
    info: {
      title: 'SHA-256 — How it works',
      body: `
        <p>SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that produces a fixed-length 256-bit (64 hex character) digest from any input. It is a <strong>one-way function</strong> — you cannot reverse a hash to recover the original text.</p>
        <p><strong>Example:</strong> "hello" → "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"</p>
        <p><strong>Use cases:</strong> Password storage, data integrity verification, digital signatures, blockchain.</p>
        <p><strong>Security:</strong> Collision-resistant and pre-image resistant. Cannot be decrypted — only compared.</p>
        <p><strong>Note:</strong> Requires a PHP server to run.</p>
      `
    }
  }
};

/* ══════════════════════════════════════════════════════════════
   DOM REFERENCES
   ══════════════════════════════════════════════════════════════ */
const $ = id => document.getElementById(id);

const els = {
  inputText:    $('inputText'),
  outputText:   $('outputText'),
  charCount:    $('charCount'),
  shiftKey:     $('shiftKey'),
  vigenereKey:  $('vigenereKey'),
  aesKey:       $('aesKey'),
  fieldShift:   $('fieldShift'),
  fieldVigenere:$('fieldVigenere'),
  fieldAES:     $('fieldAES'),
  runBtn:       $('runBtn'),
  runBtnText:   $('runBtnText'),
  btnLoader:    $('btnLoader'),
  btnEncrypt:   $('btnEncrypt'),
  btnDecrypt:   $('btnDecrypt'),
  toolAlgoBadge:$('toolAlgoBadge'),
  toolAlgoType: $('toolAlgoType'),
  inputLabel:   $('inputLabel'),
  outputLabel:  $('outputLabel'),
  timingBadge:  $('timingBadge'),
  timingText:   $('timingText'),
  toolNotice:   $('toolNotice'),
  arrowIcon:    $('arrowIcon'),
  outputInfo:   $('outputInfo'),
  infoInputLen: $('infoInputLen'),
  infoOutputLen:$('infoOutputLen'),
  infoTime:     $('infoTime'),
  infoAlgo:     $('infoAlgo'),
  algoInfoBox:  $('algoInfoBox'),
  infoBoxTitle: $('infoBoxTitle'),
  infoBoxBody:  $('infoBoxBody'),
  statEnc:      $('statEnc'),
  statDec:      $('statDec'),
};

/* ══════════════════════════════════════════════════════════════
   INIT
   ══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  selectAlgo('caesar');
  initAlgoCards();
  initCharCounter();
  initBinaryRain();
  initNavToggle();
  loadStats();
  // Auth nav injection (auth.js loaded before app.js in updated index.html)
  if (typeof CV_Auth !== 'undefined') CV_Auth.initNav();
});

/* ══════════════════════════════════════════════════════════════
   ALGO CARD SELECTION
   ══════════════════════════════════════════════════════════════ */
function initAlgoCards() {
  document.querySelectorAll('.algo-card').forEach(card => {
    card.addEventListener('click', () => selectAlgo(card.dataset.algo));
  });
}

function selectAlgo(algo) {
  currentAlgo = algo;
  const meta = ALGO_META[algo];
  if (!meta) return;

  // Update card highlight
  document.querySelectorAll('.algo-card').forEach(c => {
    c.classList.toggle('selected', c.dataset.algo === algo);
  });

  // Update tool header
  els.toolAlgoBadge.textContent = meta.label;
  els.toolAlgoType.textContent  = meta.type;

  // Show/hide key fields
  els.fieldShift.classList.add('hidden');
  els.fieldVigenere.classList.add('hidden');
  els.fieldAES.classList.add('hidden');

  if (meta.keyField === 'shift')    els.fieldShift.classList.remove('hidden');
  if (meta.keyField === 'vigenere') els.fieldVigenere.classList.remove('hidden');
  if (meta.keyField === 'aes')      els.fieldAES.classList.remove('hidden');

  // Disable decrypt for one-way algos
  if (meta.decryptDisabled) {
    els.btnDecrypt.disabled = true;
    els.btnDecrypt.title    = 'SHA-256 is a one-way hash — it cannot be reversed.';
    if (currentMode === 'decrypt') setMode('encrypt');
  } else {
    els.btnDecrypt.disabled = false;
    els.btnDecrypt.title    = '';
  }

  // Update algo info box
  els.infoBoxTitle.textContent  = meta.info.title;
  els.infoBoxBody.innerHTML     = meta.info.body;

  // Update labels
  updateLabels();

  // Clear output
  els.outputText.value = '';
  els.outputInfo.style.display = 'none';
  els.timingBadge.style.display = 'none';
  hideNotice();
}

/* ══════════════════════════════════════════════════════════════
   MODE TOGGLE
   ══════════════════════════════════════════════════════════════ */
function setMode(mode) {
  currentMode = mode;
  els.btnEncrypt.classList.toggle('active', mode === 'encrypt');
  els.btnDecrypt.classList.toggle('active', mode === 'decrypt');
  updateLabels();
  els.outputText.value = '';
  els.outputInfo.style.display = 'none';
  els.timingBadge.style.display = 'none';
  hideNotice();
}

function updateLabels() {
  if (currentMode === 'encrypt') {
    els.inputLabel.textContent  = 'Plaintext';
    els.outputLabel.textContent = 'Ciphertext';
    els.runBtnText.textContent  = '🔒 Encrypt';
    els.inputText.placeholder   = 'Enter text to encrypt...';
    els.outputText.placeholder  = 'Encrypted output will appear here...';
    els.arrowIcon.textContent   = '→';
  } else {
    els.inputLabel.textContent  = 'Ciphertext';
    els.outputLabel.textContent = 'Plaintext';
    els.runBtnText.textContent  = '🔓 Decrypt';
    els.inputText.placeholder   = 'Enter ciphertext to decrypt...';
    els.outputText.placeholder  = 'Decrypted output will appear here...';
    els.arrowIcon.textContent   = '←';
  }
}

/* ══════════════════════════════════════════════════════════════
   CHAR COUNTER
   ══════════════════════════════════════════════════════════════ */
function initCharCounter() {
  els.inputText.addEventListener('input', () => {
    els.charCount.textContent = els.inputText.value.length;
  });
}

/* ══════════════════════════════════════════════════════════════
   MAIN CRYPTO DISPATCH
   ══════════════════════════════════════════════════════════════ */
async function runCrypto() {
  const text = els.inputText.value;
  if (!text.trim()) { showNotice('Please enter some text first.', 'warning'); return; }

  hideNotice();
  setLoading(true);

  const meta = ALGO_META[currentAlgo];

  try {
    let result, timeMs;

    if (meta.backend === 'php') {
      ({ result, timeMs } = await runPHP(currentAlgo, currentMode, text));
    } else {
      ({ result, timeMs } = runJS(currentAlgo, currentMode, text));
    }

    els.outputText.value = result;

    // Save to history if user is logged in
    saveToHistory(currentAlgo, meta.label, currentMode, text, result, timeMs);

    // Update stats
    if (currentMode === 'encrypt') {
      encryptCount++;
      els.statEnc.textContent = encryptCount;
    } else {
      decryptCount++;
      els.statDec.textContent = decryptCount;
    }
    saveStats();

    // Show timing
    els.timingText.textContent      = timeMs < 1 ? '<1ms' : `${timeMs.toFixed(2)}ms`;
    els.timingBadge.style.display   = 'flex';

    // Show info strip
    els.infoInputLen.textContent  = text.length + ' chars';
    els.infoOutputLen.textContent = result.length + ' chars';
    els.infoTime.textContent      = timeMs < 1 ? '<1ms' : `${timeMs.toFixed(2)}ms`;
    els.infoAlgo.textContent      = meta.label;
    els.outputInfo.style.display  = 'grid';

  } catch (err) {
    showNotice(err.message, 'error');
    els.outputText.value = '';
    els.outputInfo.style.display = 'none';
    els.timingBadge.style.display = 'none';
  } finally {
    setLoading(false);
  }
}

/* ── JS-side dispatch ───────────────────────────────────────── */
function runJS(algo, mode, text) {
  const t0 = performance.now();
  let result;

  switch (algo) {
    case 'caesar': {
      const shift = parseInt(els.shiftKey.value, 10);
      if (isNaN(shift) || shift < 1 || shift > 25) throw new Error('Shift key must be between 1 and 25.');
      result = mode === 'encrypt'
        ? Algorithms.caesarEncrypt(text, shift)
        : Algorithms.caesarDecrypt(text, shift);
      break;
    }
    case 'rot13':
      result = Algorithms.rot13(text);
      break;

    case 'atbash':
      result = Algorithms.atbash(text);
      break;

    case 'vigenere': {
      const key = els.vigenereKey.value.trim();
      if (!key) throw new Error('Please enter a keyword for the Vigenère cipher.');
      if (!/^[a-zA-Z]+$/.test(key)) throw new Error('Vigenère keyword must contain letters only.');
      result = mode === 'encrypt'
        ? Algorithms.vigenereEncrypt(text, key)
        : Algorithms.vigenereDecrypt(text, key);
      break;
    }
    case 'base64':
      result = mode === 'encrypt'
        ? Algorithms.base64Encode(text)
        : Algorithms.base64Decode(text);
      break;

    default:
      throw new Error(`Unknown algorithm: ${algo}`);
  }

  const timeMs = performance.now() - t0;
  return { result, timeMs };
}

/* ── PHP-side dispatch ──────────────────────────────────────── */
async function runPHP(algo, mode, text) {
  const key = algo === 'aes' ? els.aesKey.value : '';

  if (algo === 'aes' && key.length < 8) {
    throw new Error('AES passphrase must be at least 8 characters.');
  }

  const t0 = performance.now();

  let response;
  try {
    response = await fetch(PHP_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ algo, mode, text, key }),
    });
  } catch (networkErr) {
    throw new Error(
      'Cannot reach the PHP backend. Make sure you are running this through a PHP server (e.g. XAMPP, WAMP, or php -S localhost:8000).'
    );
  }

  const json = await response.json();
  const timeMs = performance.now() - t0;

  if (!json.success) {
    throw new Error(json.error || 'PHP backend returned an error.');
  }

  return { result: json.data.output, timeMs: json.data.time_ms ?? timeMs };
}

/* ══════════════════════════════════════════════════════════════
   UTILITY ACTIONS
   ══════════════════════════════════════════════════════════════ */

/** Clear both text areas */
function clearAll() {
  els.inputText.value  = '';
  els.outputText.value = '';
  els.charCount.textContent = '0';
  els.outputInfo.style.display  = 'none';
  els.timingBadge.style.display = 'none';
  hideNotice();
}

/** Swap input ↔ output */
function swapIO() {
  const tmp = els.inputText.value;
  els.inputText.value  = els.outputText.value;
  els.outputText.value = tmp;
  els.charCount.textContent = els.inputText.value.length;
  els.outputInfo.style.display  = 'none';
  els.timingBadge.style.display = 'none';
  hideNotice();
}

/** Copy output to clipboard */
async function copyOutput() {
  const text = els.outputText.value;
  if (!text) { showNotice('Nothing to copy yet.', 'warning'); return; }

  try {
    await navigator.clipboard.writeText(text);
    showToast('✓ Copied to clipboard!');
  } catch {
    // Fallback for non-HTTPS
    els.outputText.select();
    document.execCommand('copy');
    showToast('✓ Copied!');
  }
}

/** Download output as .txt */
function downloadOutput() {
  const text = els.outputText.value;
  if (!text) { showNotice('Nothing to download yet.', 'warning'); return; }

  const blob = new Blob([text], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const algo = ALGO_META[currentAlgo].label.replace(/\s+/g, '_');
  const mode = currentMode;
  a.href     = url;
  a.download = `cryptovault_${algo}_${mode}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Toggle AES passphrase visibility */
function toggleAESKey() {
  const field = els.aesKey;
  field.type = field.type === 'password' ? 'text' : 'password';
}

/* ══════════════════════════════════════════════════════════════
   LOADING STATE
   ══════════════════════════════════════════════════════════════ */
function setLoading(on) {
  els.runBtn.disabled = on;
  els.runBtnText.classList.toggle('hidden', on);
  els.btnLoader.classList.toggle('hidden', !on);
}

/* ══════════════════════════════════════════════════════════════
   NOTICES & TOAST
   ══════════════════════════════════════════════════════════════ */
function showNotice(msg, type = 'error') {
  els.toolNotice.textContent = msg;
  els.toolNotice.className   = `tool-notice ${type}`;
  els.toolNotice.classList.remove('hidden');
}

function hideNotice() {
  els.toolNotice.classList.add('hidden');
}

function showToast(msg) {
  const t = document.createElement('div');
  t.className   = 'copied-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2100);
}

/* ══════════════════════════════════════════════════════════════
   HISTORY SAVE
   ══════════════════════════════════════════════════════════════ */

/** Fire-and-forget: save one operation to the user's history */
async function saveToHistory(algo, algoLabel, mode, inputText, outputText, timeMs) {
  const token = (typeof CV_Auth !== 'undefined') ? CV_Auth.getToken() : null;
  if (!token) return; // not logged in — skip

  try {
    await fetch(HISTORY_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Token': token },
      body: JSON.stringify({
        action:        'save',
        algorithm:     algo,
        algo_label:    algoLabel,
        mode,
        input_text:    inputText,
        output_text:   outputText,
        input_length:  inputText.length,
        output_length: outputText.length,
        time_ms:       timeMs,
      }),
    });
  } catch { /* silent — don't block the UI */ }
}

/* ══════════════════════════════════════════════════════════════
   STATS PERSISTENCE
   ══════════════════════════════════════════════════════════════ */
function saveStats() {
  try {
    localStorage.setItem('cv_enc', encryptCount);
    localStorage.setItem('cv_dec', decryptCount);
  } catch {}
}

function loadStats() {
  try {
    encryptCount = parseInt(localStorage.getItem('cv_enc') || '0', 10);
    decryptCount = parseInt(localStorage.getItem('cv_dec') || '0', 10);
    if (els.statEnc) els.statEnc.textContent = encryptCount;
    if (els.statDec) els.statDec.textContent = decryptCount;
  } catch {}

  // Also pull server stats if logged in
  if (typeof CV_Auth !== 'undefined' && CV_Auth.getToken()) {
    CV_Auth.apiPost(HISTORY_ENDPOINT, { action: 'stats' }).then(res => {
      if (res.success && res.totals) {
        const t = res.totals;
        if (els.statEnc) els.statEnc.textContent = t.encryptions || encryptCount;
        if (els.statDec) els.statDec.textContent = t.decryptions || decryptCount;
      }
    }).catch(() => {});
  }
}

/* ══════════════════════════════════════════════════════════════
   BINARY RAIN ANIMATION
   ══════════════════════════════════════════════════════════════ */
function initBinaryRain() {
  const container = document.getElementById('binaryRain');
  if (!container) return;

  const COLS = 22, ROWS = 18;
  const chars = '01アイウエカキクケサシスタチツナニヌネハヒフヘマミムメ';

  let grid = Array.from({ length: ROWS }, () =>
    Array.from({ length: COLS }, () => pickChar(chars))
  );

  function pickChar(pool) { return pool[Math.floor(Math.random() * pool.length)]; }

  function render() {
    container.textContent = grid.map(row => row.join(' ')).join('\n');
  }

  function tick() {
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        if (Math.random() < 0.04) grid[r][c] = pickChar(chars);
      }
    }
    render();
  }

  render();
  setInterval(tick, 120);
}

/* ══════════════════════════════════════════════════════════════
   NAV TOGGLE (mobile)
   ══════════════════════════════════════════════════════════════ */
function initNavToggle() {
  const btn   = document.getElementById('navToggle');
  const links = document.querySelector('.nav-links');
  if (!btn || !links) return;
  btn.addEventListener('click', () => links.classList.toggle('open'));
}
