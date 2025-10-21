// src/worker.ts
export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string; // secret (used for submit + detail view)
  MAIL_FROM: string;      // e.g., "W4TRC Nets <no-reply@w4trc.org>"
  MAIL_FROM_NAME: string; // (not used by Resend; kept for compatibility)
  DISTRO?: string;        // comma-separated, static in wrangler.jsonc "vars"
  RESEND_API_KEY: string; // secret
}

/* ---------- HTML shell + styles ---------- */
const HTML = (body: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>W4TRC Net Logging</title>
<style>
  :root {
    --bg: #0b0f19; --panel: #101724; --panel-2:#0e1424;
    --border: #1f2847; --text:#eef2ff; --muted:#9fb0ff;
    --accent:#263462; --accent-b:#3f4d7f; --ok:#0f2d1a; --okb:#1d5d36; --err:#2d0f14; --errb:#5d1d27;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; background: var(--bg); color: var(--text); }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 28px 24px 64px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 18px; padding: 22px; box-shadow: 0 12px 34px rgba(0,0,0,.28); }
  h1 { font-size: 1.9rem; margin: 0 0 6px; }
  h2 { margin: 0 0 12px; }
  p.muted { color: var(--muted); margin: 0 0 16px; }
  label { display:block; font-weight:600; margin: 12px 0 6px; }
  input, textarea {
    width: 100%; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border);
    background: var(--panel-2); color: var(--text); outline: none;
  }
  input[type="date"], input[type="number"] { padding: 10px 12px; }
  textarea { resize: vertical; }
  .grid-2 {
    display: grid; gap: 14px;
    grid-template-columns: 1fr;
  }
  @media (min-width: 900px) {
    .grid-2 { grid-template-columns: 1fr 1fr; }
  }
  .btn {
    display: inline-block; padding: 11px 16px; border-radius: 12px; border: 1px solid var(--accent-b);
    background: var(--accent); color: #fff; font-weight: 700; cursor: pointer; margin-top: 14px; text-decoration:none;
  }
  .btn-ghost { background: transparent; border-color: var(--border); }
  table { width:100%; border-collapse: collapse; margin-top: 12px; }
  th, td { padding: 10px 8px; border-bottom: 1px solid var(--border); text-align:left; }
  th { color: var(--muted); }
  .ok { background: var(--ok); border:1px solid var(--okb); padding:10px 12px; border-radius: 10px; margin-bottom:12px; }
  .err { background: var(--err); border:1px solid var(--errb); padding:10px 12px; border-radius: 10px; margin-bottom:12px; }
  a { color: #b0c4ff; }
  .spacer { height: 6px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap; }
  .row { display:flex; gap:10px; flex-wrap: wrap; margin-top: 8px; }
</style>
</head>
<body>
  <div class="wrap">${body}</div>
</body>
</html>`;

/* ---------- Small helpers ---------- */
function redirect(to: string, code = 302) {
  return new Response(null, { status: code, headers: { Location: to } });
}
function textOrUndefined(v: unknown) { return (typeof v === 'string' && v.trim().length) ? v.trim() : undefined; }
function intOrZero(v: unknown) { const n = Number(v); return Number.isFinite(n) ? Math.floor(n) : 0; }
function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c] as string));
}
function requireAuth(formPassword: string | undefined, env: Env) {
  return formPassword && formPassword === env.ADMIN_PASSWORD;
}
function hasAuthCookie(request: Request) {
  const cookie = request.headers.get("cookie") || "";
  return /net_auth=1/.test(cookie);
}
function authCookie() {
  // 30-minute session cookie for detail pages
  return `net_auth=1; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/* ---------- Email via Resend ---------- */
async function sendMail(env: Env, subject: string, htmlBody: string) {
  const toList = (env.DISTRO ?? '').split(',').map(s => s.trim()).filter(Boolean);
  if (!toList.length) return { ok: true, skipped: true };

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "authorization": `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      from: env.MAIL_FROM,         // e.g., "W4TRC Nets <no-reply@w4trc.org>"
      to: toList,                  // array of recipients
      subject,
      html: htmlBody
    })
  });

  return { ok: r.ok, status: r.status, statusText: r.statusText };
}

/* ---------- Route handlers ---------- */
async function handleHome() {
  return redirect('https://w4trc.org/nets', 301);
}

async function handleSubmitGET() {
  const today = new Date().toISOString().slice(0,10);
  const body = `
    <div class="card">
      <h1>W4TRC Net Submission</h1>
      <p class="muted">Submit totals for the weekly net. Fields marked * are required.</p>

      <form method="post" action="/submit">
        <div class="grid-2">
          <div>
            <label for="net_date">Net Date *</label>
            <input id="net_date" name="net_date" type="date" required value="${today}" />
          </div>
          <div>
            <label for="password">Passcode *</label>
            <input id="password" name="password" type="password" placeholder="Shared passcode" required />
          </div>
        </div>

        <div class="grid-2">
          <div>
            <label for="net_control_callsign">Net Control Callsign *</label>
            <input id="net_control_callsign" name="net_control_callsign" required placeholder="e.g., W4TRC" />
          </div>
          <div>
            <label for="net_control_name">Net Control Name *</label>
            <input id="net_control_name" name="net_control_name" required placeholder="Full name" />
          </div>
        </div>

        <div>
          <label for="check_ins_count"># of Check-ins *</label>
          <input id="check_ins_count" name="check_ins_count" type="number" min="0" required />
        </div>

        <div class="spacer"></div>

        <div>
          <label for="check_ins_list">List of Check-ins (one per line or comma-separated)</label>
          <textarea id="check_ins_list" name="check_ins_list" rows="7" placeholder="K4ABC, KN4XYZ, ..."></textarea>
        </div>

        <div>
          <label for="comments">Comments</label>
          <textarea id="comments" name="comments" rows="6" placeholder="Anything notable about the net..."></textarea>
        </div>

        <button class="btn" type="submit">Save</button>
      </form>
      <p class="muted" style="margin-top:10px;">After submission, totals become visible on <a href="/view">/view</a>.</p>
    </div>
  `;
  return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

async function handleSubmitPOST(request: Request, env: Env) {
  const form = await request.formData();
  const password = textOrUndefined(form.get('password'));
  if (!requireAuth(password, env)) {
    const body = `<div class="card err"><strong>Access denied.</strong> Invalid passcode.</div>`;
    return new Response(HTML(body), { status: 401, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  const net_date = textOrUndefined(form.get('net_date'));
  const net_control_callsign = textOrUndefined(form.get('net_control_callsign'));
  const net_control_name = textOrUndefined(form.get('net_control_name'));
  const check_ins_count = intOrZero(form.get('check_ins_count'));
  const check_ins_list = textOrUndefined(form.get('check_ins_list')) ?? '';
  const comments = textOrUndefined(form.get('comments')) ?? '';

  if (!net_date || !net_control_callsign || !net_control_name || Number.isNaN(check_ins_count)) {
    const body = `<div class="card err"><strong>Missing required fields.</strong> Please check the form and try again.</div>`;
    return new Response(HTML(body), { status: 400, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  // Insert
  const stmt = env.DB.prepare(
    `INSERT INTO nets (net_date, net_control_callsign, net_control_name, check_ins_count, check_ins_list, comments)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  ).bind(net_date, net_control_callsign, net_control_name, check_ins_count, check_ins_list, comments);

  const result = await stmt.run();

  // Email via static distro (includes comments since you left them in the email body)
  const subject = `W4TRC Net: ${net_date} — ${check_ins_count} check-ins (${net_control_callsign})`;
  const htmlBody = `
    <h2>W4TRC Net Report — ${net_date}</h2>
    <p><strong>Net Control:</strong> ${escapeHtml(net_control_name)} (${escapeHtml(net_control_callsign)})<br/>
       <strong>Check-ins:</strong> ${check_ins_count}</p>
    <p><strong>List:</strong><br/><pre>${escapeHtml(check_ins_list)}</pre></p>
    <p><strong>Comments:</strong><br/><pre>${escapeHtml(comments)}</pre></p>
    <p>View all: <a href="https://nets.w4trc.org/view">https://nets.w4trc.org/view</a></p>
  `;
  await sendMail(env, subject, htmlBody);

  const body = `
    <div class="card">
      <div class="ok"><strong>Saved!</strong> Thanks for sending your log.</div>
      <h2>Submission recorded</h2>
      <p>
        <a class="btn" href="/submit">Submit another</a>
        &nbsp; <a class="btn btn-ghost" href="/view">Go to View</a>
        ${result.success ? `&nbsp; <a class="btn btn-ghost" href="/net/${result.lastRowId}">View this entry</a>` : ``}
      </p>
    </div>`;
  return new Response(HTML(body), {
    headers: { 'content-type': 'text/html; charset=utf-8', 'set-cookie': authCookie() }
  });
}

async function handleView(env: Env) {
  const { results } = await env.DB.prepare(
    `SELECT id, net_date, net_control_callsign, net_control_name, check_ins_count
     FROM nets ORDER BY net_date DESC, id DESC LIMIT 2000`
  ).all();

  const rows = (results ?? []).map((r: any) => `
    <tr>
      <td><a href="/net/${r.id}">${r.net_date}</a></td>
      <td>${escapeHtml(r.net_control_callsign)}</td>
      <td>${escapeHtml(r.net_control_name)}</td>
      <td>${r.check_ins_count}</td>
    </tr>`).join('');

  const body = `
    <div class="card">
      <h1>W4TRC Nets — History</h1>
      <p class="muted">Click a date to view full details. Comments are visible on detail pages only (requires passcode once per session).</p>
      <table>
        <thead><tr><th>Date</th><th>Control (Call)</th><th>Control (Name)</th><th># Check-ins</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4">No records yet.</td></tr>`}</tbody>
      </table>
    </div>`;
  return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

/* ----- Per-net detail (protected by passcode once per session) ----- */
async function handleNetDetailGET(request: Request, env: Env, id: number) {
  if (!hasAuthCookie(request)) {
    const body = `
      <div class="card">
        <h1>View Net Details</h1>
        <p class="muted">Enter the passcode to view check-ins and comments for this entry.</p>
        <form method="post" action="/net/${id}">
          <label for="password">Passcode *</label>
          <input id="password" name="password" type="password" required />
          <button class="btn" type="submit">View Details</button>
          <a class="btn btn-ghost" href="/view">Back to list</a>
        </form>
      </div>`;
    return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  return await renderNetDetail(env, id);
}

async function handleNetDetailPOST(request: Request, env: Env, id: number) {
  const form = await request.formData();
  const password = textOrUndefined(form.get('password'));
  if (!requireAuth(password, env)) {
    const body = `<div class="card err"><strong>Access denied.</strong> Invalid passcode.</div>`;
    return new Response(HTML(body), { status: 401, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  const res = await renderNetDetail(env, id);
  res.headers.append('set-cookie', authCookie());
  return res;
}

async function renderNetDetail(env: Env, id: number) {
  const row = await env.DB.prepare(
    `SELECT id, net_date, net_control_callsign, net_control_name, check_ins_count, check_ins_list, comments, created_at
     FROM nets WHERE id = ?1`
  ).bind(id).first();
  if (!row) {
    return new Response(HTML(`<div class="card err"><strong>Not found.</strong></div>`), {
      status: 404,
      headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  }

  const body = `
    <div class="card">
      <h1>Net Details — ${row.net_date}</h1>
      <p class="muted">Entry #${row.id} • Created ${escapeHtml(row.created_at)}</p>
      <div class="grid-2">
        <div>
          <label>Net Control (Callsign)</label>
          <input readonly value="${escapeHtml(row.net_control_callsign)}"/>
        </div>
        <div>
          <label>Net Control (Name)</label>
          <input readonly value="${escapeHtml(row.net_control_name)}"/>
        </div>
      </div>
      <div style="margin-top:10px;">
        <label># of Check-ins</label>
        <input readonly value="${row.check_ins_count}"/>
      </div>

      <div style="margin-top:14px;">
        <label>Check-ins List</label>
        <div class="card" style="padding:12px; margin-top:4px;">
          <div class="mono">${escapeHtml(row.check_ins_list || '')}</div>
        </div>
      </div>

      <div style="margin-top:14px;">
        <label>Comments</label>
        <div class="card" style="padding:12px; margin-top:4px;">
          <div class="mono">${escapeHtml(row.comments || '')}</div>
        </div>
      </div>

      <p class="row">
        <a class="btn btn-ghost" href="/view">Back to list</a>
      </p>
    </div>
  `;
  return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

/* ----- JSON endpoints for Hugo / analysis ----- */
async function handleApiStats(env: Env) {
  const last = await env.DB.prepare(
    `SELECT net_date, check_ins_count FROM nets ORDER BY net_date DESC, id DESC LIMIT 1`
  ).first();

  const today = new Date().toISOString().slice(0,10);
  const d90 = new Date(Date.now() - 90*24*3600*1000).toISOString().slice(0,10);
  const d180 = new Date(Date.now() - 180*24*3600*1000).toISOString().slice(0,10);

  const avg90 = await env.DB.prepare(
    `SELECT avg(check_ins_count) as avg FROM nets WHERE net_date >= ?1 AND net_date <= ?2`
  ).bind(d90, today).first();

  const avg180 = await env.DB.prepare(
    `SELECT avg(check_ins_count) as avg FROM nets WHERE net_date >= ?1 AND net_date <= ?2`
  ).bind(d180, today).first();

  const payload = {
    last_check_ins: last?.check_ins_count ?? null,
    last_date: last?.net_date ?? null,
    avg_90d: round2(avg90?.avg),
    avg_180d: round2(avg180?.avg),
    generated_at: new Date().toISOString(),
  };

  return new Response(JSON.stringify(payload), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*'
    }
  });
}

async function handleApiNets(env: Env, request: Request) {
  const url = new URL(request.url);
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '500'), 2000);
  const { results } = await env.DB.prepare(
    `SELECT id, net_date, net_control_callsign, net_control_name, check_ins_count, check_ins_list, created_at
     FROM nets ORDER BY net_date DESC, id DESC LIMIT ?1`
  ).bind(limit).all();

  return new Response(JSON.stringify(results ?? []), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*'
    }
  });
}

function round2(n: any) {
  const x = Number(n);
  return Number.isFinite(x) ? Math.round(x * 100)/100 : null;
}

/* ---------- Worker fetch ---------- */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === "/" || pathname === "") return handleHome();

    if (pathname === "/submit" && request.method === "GET") return handleSubmitGET();
    if (pathname === "/submit" && request.method === "POST") return handleSubmitPOST(request, env);

    if (pathname === "/view" && request.method === "GET") return handleView(env);

    // Per-net detail: /net/:id (GET to prompt/login or show; POST to authenticate)
    if (pathname.startsWith("/net/")) {
      const idStr = pathname.slice("/net/".length).trim();
      const id = Number(idStr);
      if (!Number.isFinite(id) || id <= 0) return new Response("Bad ID", { status: 400 });
      if (request.method === "GET") return handleNetDetailGET(request, env, id);
      if (request.method === "POST") return handleNetDetailPOST(request, env, id);
    }

    if (pathname === "/api/stats" && request.method === "GET") return handleApiStats(env);
    if (pathname === "/api/nets" && request.method === "GET") return handleApiNets(env, request);

    // CORS preflight for /api/*
    if (pathname.startsWith("/api/") && request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, OPTIONS",
          "access-control-allow-headers": "content-type"
        }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
