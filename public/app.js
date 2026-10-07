(() => {
  const API = '/api/v1';
  let accessToken = null; // memory only, never localStorage

  const $ = (id) => document.getElementById(id);
  const out = $('output');
  const status = $('session-status');
  const tokenBox = $('token-box');

  function show(label, res, body) {
    out.textContent = `${label}\nHTTP ${res.status}\n\n${JSON.stringify(body, null, 2)}`;
    out.className = res.ok ? 'ok' : 'err';
  }

  function setSession(data) {
    accessToken = data?.accessToken || null;
    tokenBox.value = accessToken || '';
    status.textContent = data?.user
      ? `Signed in as ${data.user.name} (${data.user.email}) with role ${data.user.role}`
      : 'Not signed in.';
  }

  async function call(method, path, body, withAuth = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (withAuth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const res = await fetch(API + path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    return { res, data };
  }

  async function refresh(label = 'POST /auth/refresh') {
    const { res, data } = await call('POST', '/auth/refresh', null, false);
    if (res.ok) setSession(data); else setSession(null);
    show(label, res, data);
    return res.ok;
  }

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const { res, data } = await call(
      'POST',
      '/auth/login',
      { email: $('login-email').value, password: $('login-password').value },
      false
    );
    if (res.ok) setSession(data);
    show('POST /auth/login', res, data);
  });

  $('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const { res, data } = await call(
      'POST',
      '/auth/register',
      { name: $('reg-name').value, email: $('reg-email').value, password: $('reg-password').value },
      false
    );
    show('POST /auth/register', res, data);
  });

  $('refresh-btn').addEventListener('click', () => refresh());

  $('logout-btn').addEventListener('click', async () => {
    const { res, data } = await call('POST', '/auth/logout', null, false);
    setSession(null);
    show('POST /auth/logout', res, data);
  });

  document.querySelectorAll('[data-call]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = $('target-id').value.trim();
      let r;
      switch (btn.dataset.call) {
        case 'profile':
          r = await call('GET', '/employee/profile');
          break;
        case 'approve':
          r = await call('POST', '/payroll/approve', { employeeId: id, amount: 1500, period: '2026-10' });
          break;
        case 'users':
          r = await call('GET', '/users');
          break;
        case 'delete':
          r = await call('DELETE', `/users/${encodeURIComponent(id)}`);
          break;
      }
      show(`${btn.textContent}`, r.res, r.data);
    });
  });

  // Provider buttons: hide ones that are not configured on the server
  fetch(`${API}/auth/providers`)
    .then((r) => r.json())
    .then((p) => {
      if (!p.google) $('google-btn').style.display = 'none';
      if (!p.github) $('github-btn').style.display = 'none';
    })
    .catch(() => {});

  // Returning from OAuth: the callback set the refresh cookie, so exchange it for an access token
  const params = new URLSearchParams(window.location.search);
  if (params.get('oauth') === 'success') {
    history.replaceState(null, '', '/');
    refresh('OAuth login complete: POST /auth/refresh');
  } else if (params.get('oauth') === 'failed') {
    history.replaceState(null, '', '/');
    out.textContent = 'OAuth login failed or was cancelled.';
    out.className = 'err';
  }
})();
