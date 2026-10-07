/**
 * CryptoVault — algorithms.js
 * Pure JavaScript implementations of classical cryptographic algorithms.
 * AES-256 and SHA are handled server-side via PHP.
 */

'use strict';

const Algorithms = (() => {

  /* ─────────────────────────────────────────────
     CAESAR CIPHER
     Shift each alpha character by key (1–25)
  ───────────────────────────────────────────── */
  function caesarEncrypt(text, shift) {
    shift = ((parseInt(shift, 10) % 26) + 26) % 26;
    return text.split('').map(ch => {
      if (/[a-z]/.test(ch)) return String.fromCharCode(((ch.charCodeAt(0) - 97 + shift) % 26) + 97);
      if (/[A-Z]/.test(ch)) return String.fromCharCode(((ch.charCodeAt(0) - 65 + shift) % 26) + 65);
      return ch;
    }).join('');
  }

  function caesarDecrypt(text, shift) {
    return caesarEncrypt(text, 26 - ((parseInt(shift, 10) % 26 + 26) % 26));
  }

  /* ─────────────────────────────────────────────
     ROT13
     Caesar with fixed shift of 13
  ───────────────────────────────────────────── */
  function rot13(text) {
    return caesarEncrypt(text, 13); // encrypt == decrypt for ROT13
  }

  /* ─────────────────────────────────────────────
     ATBASH CIPHER
     A↔Z, B↔Y, C↔X … no key required
  ───────────────────────────────────────────── */
  function atbash(text) {
    return text.split('').map(ch => {
      if (/[a-z]/.test(ch)) return String.fromCharCode(122 - (ch.charCodeAt(0) - 97));
      if (/[A-Z]/.test(ch)) return String.fromCharCode(90  - (ch.charCodeAt(0) - 65));
      return ch;
    }).join('');
  }

  /* ─────────────────────────────────────────────
     VIGENÈRE CIPHER
     Polyalphabetic substitution with keyword
  ───────────────────────────────────────────── */
  function vigenereEncrypt(text, key) {
    if (!key || !/[a-zA-Z]/.test(key)) throw new Error('Keyword must contain letters.');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    let ki = 0;
    return text.split('').map(ch => {
      if (/[a-zA-Z]/.test(ch)) {
        const base   = /[a-z]/.test(ch) ? 97 : 65;
        const shift  = key.charCodeAt(ki % key.length) - 65;
        ki++;
        return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
      }
      return ch;
    }).join('');
  }

  function vigenereDecrypt(text, key) {
    if (!key || !/[a-zA-Z]/.test(key)) throw new Error('Keyword must contain letters.');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    let ki = 0;
    return text.split('').map(ch => {
      if (/[a-zA-Z]/.test(ch)) {
        const base   = /[a-z]/.test(ch) ? 97 : 65;
        const shift  = key.charCodeAt(ki % key.length) - 65;
        ki++;
        return String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26) % 26) + base);
      }
      return ch;
    }).join('');
  }

  /* ─────────────────────────────────────────────
     BASE64 ENCODING / DECODING
     Not encryption — just encoding
  ───────────────────────────────────────────── */
  function base64Encode(text) {
    try {
      return btoa(unescape(encodeURIComponent(text)));
    } catch (e) {
      throw new Error('Base64 encode failed: ' + e.message);
    }
  }

  function base64Decode(text) {
    try {
      return decodeURIComponent(escape(atob(text.trim())));
    } catch (e) {
      throw new Error('Invalid Base64 string. Make sure you are decoding valid Base64 encoded text.');
    }
  }

  /* ─────────────────────────────────────────────
     PUBLIC API
  ───────────────────────────────────────────── */
  return {
    caesarEncrypt,
    caesarDecrypt,
    rot13,
    atbash,
    vigenereEncrypt,
    vigenereDecrypt,
    base64Encode,
    base64Decode,
  };

})();
