/**
 * CryptoVault — auth.js
 * Client-side authentication helper.
 * Exposes window.CV_Auth with all auth methods used across all pages.
 *
 * Token stored in localStorage under key 'cv_token'.
 * User object cached in localStorage under key 'cv_user'.
 */

'use strict';

const CV_Auth = (() => {

  const TOKEN_KEY = 'cv_token';
  const USER_KEY  = 'cv_user';
  const AUTH_API  = 'php/auth.php';

  /* ── Cached user ── */
  let _user = null;

  /* ══════════════════════════════════════════════════════════════
     STORAGE HELPERS
     ══════════════════════════════════════════════════════════════ */
  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY) || null; } catch { return null; }
  }

  function saveToken(token) {
    try { localStorage.setItem(TOKEN_KEY, token); } catch {}
  }

  function clearToken() {
    try { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); } catch {}
  }

  function saveUser(user) {
    _user = user;
    try { localStorage.setItem(USER_KEY, JSON.stringify(user)); } catch {}
  }

  function getCachedUser() {
    if (_user) return _user;
    try {
      const raw = localStorage.getItem(USER_KEY);
      if (raw) { _user = JSON.parse(raw); return _user; }
    } catch {}
    return null;
  }

  /* ══════════════════════════════════════════════════════════════
     CORE API CALLER
     ══════════════════════════════════════════════════════════════ */
  async function apiPost(endpoint, body) {
    const token = getToken();
    try {
      const res = await fetch(endpoint, {
        method:  'POST',
        headers: {
          'Content-Type':    'application/json',
          ...(token ? { 'X-Session-Token': token } : {}),
        },
        body: JSON.stringify(body),
      });
      return await res.json();
    } catch (err) {
      return { success: false, error: 'Network error: ' + err.message };
    }
  }

  /* ══════════════════════════════════════════════════════════════
     AUTH ACTIONS
     ══════════════════════════════════════════════════════════════ */

  /** Register a new user. Returns { success, token?, user?, error? } */
  async function register(fullName, email, mobile, password, confirm) {
    const res = await apiPost(AUTH_API, {
      action: 'register',
      full_name: fullName,
      email,
      mobile,
      password,
      confirm,
    });
    if (res.success && res.token) {
      saveToken(res.token);
      saveUser(res.user);
    }
    return res;
  }

  /** Login with email/mobile + password. Returns { success, token?, user?, error? } */
  async function login(identifier, password) {
    const res = await apiPost(AUTH_API, { action: 'login', identifier, password });
    if (res.success && res.token) {
      saveToken(res.token);
      saveUser(res.user);
    }
    return res;
  }

  /** Logout — destroys server session + clears local storage. */
  async function logout() {
    await apiPost(AUTH_API, { action: 'logout' });
    clearToken();
    _user = null;
  }

  /**
   * Check if current token is valid against the server.
   * Returns true/false. On success, updates cached user.
   * Call this on every protected page load.
   */
  async function checkSession() {
    const token = getToken();
    if (!token) return false;
    const res = await apiPost(AUTH_API, { action: 'check' });
    if (res.success && res.user) {
      saveUser(res.user);
      return true;
    }
    clearToken();
    return false;
  }

  /** Submit ID verification */
  async function submitID(idType, idNumber, idName) {
    return await apiPost(AUTH_API, {
      action: 'submit_id',
      id_type:   idType,
      id_number: idNumber,
      id_name:   idName,
    });
  }

  /* ══════════════════════════════════════════════════════════════
     NAV RENDERER
     Reads session state and updates the navbar on any page.
     Call initNav() once per page after DOMContentLoaded.
     ══════════════════════════════════════════════════════════════ */
  function initNav() {
    const user  = getCachedUser();
    const token = getToken();
    if (!token || !user) {
      renderGuestNav();
    } else {
      renderUserNav(user);
    }
  }

  function renderGuestNav() {
    // Replace any existing auth nav items
    const navLinks = document.querySelector('.nav-links');
    if (!navLinks) return;

    // Remove old auth nodes if re-rendering
    navLinks.querySelectorAll('[data-auth-nav]').forEach(el => el.remove());

    const loginLi  = document.createElement('li');
    loginLi.setAttribute('data-auth-nav', '1');
    loginLi.innerHTML = `<a href="login.html">Login</a>`;

    const signupLi = document.createElement('li');
    signupLi.setAttribute('data-auth-nav', '1');
    signupLi.innerHTML = `<a href="signup.html" class="nav-cta">Sign Up</a>`;

    navLinks.appendChild(loginLi);
    navLinks.appendChild(signupLi);
  }

  function renderUserNav(user) {
    const navLinks = document.querySelector('.nav-links');
    if (!navLinks) return;

    navLinks.querySelectorAll('[data-auth-nav]').forEach(el => el.remove());

    const dashLi = document.createElement('li');
    dashLi.setAttribute('data-auth-nav', '1');
    dashLi.innerHTML = `<a href="dashboard.html">🏠 Dashboard</a>`;

    const pillLi = document.createElement('li');
    pillLi.setAttribute('data-auth-nav', '1');
    pillLi.innerHTML = `
      <div class="nav-user-pill" id="navUserPill">
        <div class="nav-avatar">${user.avatar_initials || '??'}</div>
        <span>${user.full_name.split(' ')[0]}</span>
        <div class="nav-user-dropdown" id="navUserDropdown">
          <a href="dashboard.html">🏠 Dashboard</a>
          <a href="profile.html">👤 Profile</a>
          <hr style="border-color:var(--border);margin:6px 0;" />
          <a href="#" id="navLogoutBtn">🚪 Logout</a>
        </div>
      </div>`;

    navLinks.appendChild(dashLi);
    navLinks.appendChild(pillLi);

    // Wire up events after DOM insertion
    setTimeout(() => {
      const pill = document.getElementById('navUserPill');
      const drop = document.getElementById('navUserDropdown');
      const logoutBtn = document.getElementById('navLogoutBtn');

      if (pill && drop) {
        pill.addEventListener('click', (e) => {
          drop.classList.toggle('open');
          e.stopPropagation();
        });
        document.addEventListener('click', () => drop.classList.remove('open'), { once: false });
      }
      if (logoutBtn) {
        logoutBtn.addEventListener('click', async (e) => {
          e.preventDefault();
          await logout();
          window.location.href = 'login.html';
        });
      }
    }, 0);
  }

  /* ══════════════════════════════════════════════════════════════
     PUBLIC API
     ══════════════════════════════════════════════════════════════ */
  return {
    /* methods */
    getToken,
    saveToken,
    clearToken,
    saveUser,
    getCachedUser,
    apiPost,
    register,
    login,
    logout,
    checkSession,
    submitID,
    initNav,
    /* live user accessor */
    get user() { return getCachedUser(); },
  };

})();
