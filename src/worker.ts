// src/worker.ts

import * as Sentry from "@sentry/cloudflare";

export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string; // secret (used for detail view)
  MAIL_FROM: string;      // e.g., "W4TRC Nets <no-reply@w4trc.org>"
  MAIL_FROM_NAME: string; // (not used by Resend; kept for compatibility)
  DISTRO?: string;        // comma-separated, static in wrangler.jsonc "vars"
  RESEND_API_KEY: string; // secret
  TURNSTILE_SITE_KEY: string;   // public site key
  TURNSTILE_SECRET_KEY: string; // private secret key
  SENTRY_DSN?: string;          // add via wrangler secret
  SENTRY_ENVIRONMENT?: string;  // optional (e.g., "production", "staging")
  SENTRY_RELEASE?: string;      // optional (git sha/build id)
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
function hasSignupAdminCookie(request: Request) {
  const cookie = request.headers.get("cookie") || "";
  return /signup_admin=1/.test(cookie);
}
function signupAdminCookie() {
  return `signup_admin=1; Max-Age=1800; Path=/; Secure; HttpOnly; SameSite=Lax`;
}
function clearSignupAdminCookie() {
  return `signup_admin=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

type NetRole = "primary" | "backup";
type NetSignupRecord = {
  net_date: string;
  role: NetRole;
  operator_name: string;
  operator_email: string;
  operator_callsign: string;
};
type SlotAssignment = {
  operator_name: string;
  operator_callsign: string;
  source: "signup" | "override";
};
type RecurringOverrideRule = {
  label: string;
  role: NetRole;
  operator_name: string;
  operator_callsign: string;
  type: "every_n_weeks" | "nth_weekday_of_month";
  every_weeks?: number;
  anchor_date?: string;
  weekday?: number; // 0=Sun..6=Sat
  nth?: number; // 1..5
};

const RECURRING_OVERRIDES: RecurringOverrideRule[] = [
  {
    label: "George DeVault second Sunday",
    role: "primary",
    operator_name: "George DeVault",
    operator_callsign: "W3KPT",
    type: "nth_weekday_of_month",
    nth: 2,
    weekday: 0, // Sunday
  },
  {
    label: "Kevin Morrell third Sunday",
    role: "primary",
    operator_name: "Kevin Morrell",
    operator_callsign: "KM4DCK",
    type: "nth_weekday_of_month",
    nth: 3,
    weekday: 0, // Sunday
  },
];

function isValidNetDate(v: string) {
  return /^\d{4}-\d{2}-\d{2}$/.test(v);
}

function isValidEmail(v: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function normalizeCallsign(v: string) {
  return v.trim().toUpperCase();
}

function titleRole(role: NetRole) {
  return role === "primary" ? "Primary" : "Backup";
}

function formatDateDisplay(isoDate: string) {
  const [year, month, day] = isoDate.split("-").map(Number);
  const dt = new Date(Date.UTC(year, month - 1, day));
  return new Intl.DateTimeFormat("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(dt);
}

function parseIsoDateUTC(isoDate: string) {
  const [year, month, day] = isoDate.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day));
}

function toIsoDateUTC(d: Date) {
  return d.toISOString().slice(0, 10);
}

function dayDiffUTC(fromDate: Date, toDate: Date) {
  const ms = toDate.getTime() - fromDate.getTime();
  return Math.floor(ms / (24 * 3600 * 1000));
}

function matchesRecurringOverride(rule: RecurringOverrideRule, isoDate: string, defaultWeekday: number) {
  if (!isValidNetDate(isoDate)) return false;
  const date = parseIsoDateUTC(isoDate);
  const weekday = date.getUTCDay();
  const targetWeekday = rule.weekday ?? defaultWeekday;

  if (rule.type === "every_n_weeks") {
    if (!rule.anchor_date || !rule.every_weeks || rule.every_weeks < 1) return false;
    if (weekday !== targetWeekday) return false;
    const anchor = parseIsoDateUTC(rule.anchor_date);
    const days = dayDiffUTC(anchor, date);
    if (days < 0) return false;
    if (days % 7 !== 0) return false;
    const weeks = Math.floor(days / 7);
    return weeks % rule.every_weeks === 0;
  }

  if (rule.type === "nth_weekday_of_month") {
    if (!rule.nth || rule.nth < 1 || rule.nth > 5) return false;
    if (weekday !== targetWeekday) return false;
    const day = date.getUTCDate();
    const nth = Math.floor((day - 1) / 7) + 1;
    return nth === rule.nth;
  }

  return false;
}

function resolveRecurringOverride(netDate: string, role: NetRole, defaultWeekday: number): SlotAssignment | undefined {
  for (const rule of RECURRING_OVERRIDES) {
    if (rule.role !== role) continue;
    if (!matchesRecurringOverride(rule, netDate, defaultWeekday)) continue;
    return {
      operator_name: rule.operator_name,
      operator_callsign: normalizeCallsign(rule.operator_callsign),
      source: "override",
    };
  }
  return undefined;
}

function buildScheduleDates(defaultWeekday: number, fromDate: Date, horizonDays: number, maxRows: number) {
  const set = new Set<string>();
  const start = new Date(Date.UTC(fromDate.getUTCFullYear(), fromDate.getUTCMonth(), fromDate.getUTCDate()));

  for (let i = 0; i <= horizonDays; i++) {
    const d = new Date(start);
    d.setUTCDate(start.getUTCDate() + i);
    const iso = toIsoDateUTC(d);
    const weekday = d.getUTCDay();
    if (weekday === defaultWeekday) set.add(iso);

    for (const rule of RECURRING_OVERRIDES) {
      if (matchesRecurringOverride(rule, iso, defaultWeekday)) {
        set.add(iso);
        break;
      }
    }
  }

  return Array.from(set).sort((a, b) => a.localeCompare(b)).slice(0, maxRows);
}

function buildSignupFormUrl(netDate: string, role: NetRole, err?: string) {
  const base = `/signup/new?net_date=${encodeURIComponent(netDate)}&role=${encodeURIComponent(role)}`;
  if (!err) return base;
  return `${base}&err=${encodeURIComponent(err)}`;
}

function slotCell(netDate: string, role: NetRole, assignment?: SlotAssignment) {
  if (assignment) {
    const recurring = assignment.source === "override" ? `<div class="muted">Recurring assignment</div>` : "";
    return `
      <div><strong>${escapeHtml(assignment.operator_callsign)}</strong></div>
      <div>${escapeHtml(assignment.operator_name)}</div>
      ${recurring}
    `;
  }

  const signupUrl = `/signup/new?net_date=${encodeURIComponent(netDate)}&role=${encodeURIComponent(role)}`;
  return `
    <a class="btn" href="${signupUrl}">Sign up as ${titleRole(role)}</a>
  `;
}

async function verifyTurnstile(request: Request, env: Env, token: string | null) {
  if (!env.TURNSTILE_SECRET_KEY) return { success: true, skipped: true }; // fail-open if env not set (optional)
  if (!token) return { success: false, code: "MISSING_TOKEN" };

  const body = new URLSearchParams({
    secret: env.TURNSTILE_SECRET_KEY,
    response: token,
    remoteip: request.headers.get("CF-Connecting-IP") ?? ""
  });

  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body
  });

  const data = await r.json<any>();
  return data as { success: boolean; "error-codes"?: string[] };
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

async function handleSubmitGET(env?: Env) {
  const today = new Date().toISOString().slice(0,10);
  const body = `
    <div class="card">
      <h1>W4TRC Net Submission</h1>
      <p class="muted">Submit totals for the weekly net. Fields marked * are required. For any questions, please email netcontrol@w4trc.org</p>

      <!-- Turnstile loader -->
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

      <form method="post" action="/submit" autocomplete="off">
        <!-- Honeypot for basic bots -->
        <input type="text" name="website" tabindex="-1" aria-hidden="true"
               style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden;" />

        <div class="grid-2">
          <div>
            <label for="net_date">Net Date *</label>
            <input id="net_date" name="net_date" type="date" required value="${today}" />
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

        <!-- Turnstile widget (Managed mode, dark fits your theme) -->
        <div class="cf-turnstile" data-sitekey="${env?.TURNSTILE_SITE_KEY ?? ''}" data-theme="dark"></div>

        <button class="btn" type="submit">Save</button>
      </form>
      <p class="muted" style="margin-top:10px;">After submission, totals are on <a href="/view">/view</a>. Full check-ins & comments remain passcode-protected on per-entry pages.</p>
      <p class="row">
        <a class="btn btn-ghost" href="/signup">Net Sign Up</a>
      </p>
    </div>
  `;
  return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
}



async function handleSubmitPOST(request: Request, env: Env) {
  const form = await request.formData();

  // Honeypot: if filled, pretend success and bail
  const website = textOrUndefined(form.get('website'));
  if (website) {
    const body = `
      <div class="card">
        <div class="ok"><strong>Saved!</strong> Thanks for sending your log.</div>
        <p class="muted">If this was a mistake, you can <a href="/submit">try again</a>.</p>
      </div>`;
    return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  // Turnstile verification
  const token = (form.get("cf-turnstile-response") as string) ?? null;
  const outcome = await verifyTurnstile(request, env, token);
  if (!outcome.success) {
    const msg =
      ("error-codes" in outcome && Array.isArray(outcome["error-codes"]) && outcome["error-codes"].length)
        ? outcome["error-codes"].join(", ")
        : ("code" in outcome && outcome.code ? outcome.code : "Verification failed");
    const body = `<div class="card err"><strong>Human check failed.</strong> ${escapeHtml(msg)}. Please try again.</div>`;
    return new Response(HTML(body), { status: 403, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  // --- existing field parsing & insert logic (unchanged) ---
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

  const stmt = env.DB.prepare(
    `INSERT INTO nets (net_date, net_control_callsign, net_control_name, check_ins_count, check_ins_list, comments)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  ).bind(net_date, net_control_callsign, net_control_name, check_ins_count, check_ins_list, comments);

  const result = await stmt.run();
  const lastRowId = (result as any)?.meta?.last_row_id ?? (result as any)?.lastRowId;

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
        ${lastRowId ? `&nbsp; <a class="btn btn-ghost" href="/net/${lastRowId}">View this entry (passcode required)</a>` : ``}
      </p>
    </div>`;

  // inside handleSubmitPOST()
  Sentry.addBreadcrumb({ category: "net", message: "Submit POST received" });
  Sentry.setTag("net.action", "submit");
  Sentry.setUser({ ip_address: "auto" }); // already captured with sendDefaultPii, but explicit is ok

  return new Response(HTML(body), { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

async function inferNetWeekday(env: Env) {
  const { results } = await env.DB.prepare(
    `SELECT net_date FROM nets ORDER BY net_date DESC, id DESC LIMIT 24`
  ).all();

  const counts = new Array<number>(7).fill(0);
  for (const r of results ?? []) {
    const netDate = typeof (r as any).net_date === "string" ? (r as any).net_date : "";
    if (!isValidNetDate(netDate)) continue;
    const [year, month, day] = netDate.split("-").map(Number);
    const weekday = new Date(Date.UTC(year, month - 1, day)).getUTCDay();
    counts[weekday] += 1;
  }

  let bestDay = 4; // Thursday default
  let bestCount = -1;
  for (let i = 0; i < counts.length; i++) {
    if (counts[i] > bestCount) {
      bestCount = counts[i];
      bestDay = i;
    }
  }
  return bestDay;
}

async function handleSignupGET(request: Request, env: Env) {
  const weekday = await inferNetWeekday(env);
  const upcomingDates = buildScheduleDates(weekday, new Date(), 140, 20);
  const placeholders = upcomingDates.map((_, i) => `?${i + 1}`).join(", ");

  const { results } = await env.DB.prepare(
    `SELECT net_date, role, operator_name, operator_email, operator_callsign
     FROM net_signups
     WHERE net_date IN (${placeholders})
     ORDER BY net_date ASC`
  ).bind(...upcomingDates).all();

  const byDateAndRole = new Map<string, SlotAssignment>();
  for (const r of results ?? []) {
    const row = r as NetSignupRecord;
    byDateAndRole.set(`${row.net_date}:${row.role}`, {
      operator_name: row.operator_name,
      operator_callsign: row.operator_callsign,
      source: "signup",
    });
  }

  const url = new URL(request.url);
  const ok = textOrUndefined(url.searchParams.get("ok"));
  const err = textOrUndefined(url.searchParams.get("err"));

  const rows = upcomingDates
    .map((netDate) => {
      const primary = resolveRecurringOverride(netDate, "primary", weekday) ?? byDateAndRole.get(`${netDate}:primary`);
      const backup = resolveRecurringOverride(netDate, "backup", weekday) ?? byDateAndRole.get(`${netDate}:backup`);
      return `
        <tr>
          <td><strong>${escapeHtml(formatDateDisplay(netDate))}</strong></td>
          <td>${slotCell(netDate, "primary", primary)}</td>
          <td>${slotCell(netDate, "backup", backup)}</td>
        </tr>
      `;
    })
    .join("");

  const body = `
    <div class="card">
      <h1>W4TRC Net Operator Sign Up</h1>
      <p class="muted">Sign up for upcoming weekly nets. Each date has one primary and one backup net controller slot. Email addresses are kept private.</p>
      ${ok ? `<div class="ok"><strong>Saved.</strong> You are signed up for the selected slot.</div>` : ""}
      ${err ? `<div class="err"><strong>Could not save.</strong> ${escapeHtml(err)}</div>` : ""}
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>Primary Controller</th>
            <th>Backup Controller</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="row">
        <a class="btn btn-ghost" href="/submit">Submit Net Log</a>
        <a class="btn btn-ghost" href="/view">View Net History</a>
      </p>
    </div>
  `;

  return new Response(HTML(body), { headers: { "content-type": "text/html; charset=utf-8" } });
}

async function handleSignupNewGET(request: Request, env: Env) {
  const url = new URL(request.url);
  const net_date = textOrUndefined(url.searchParams.get("net_date"));
  const roleRaw = textOrUndefined(url.searchParams.get("role"));
  const err = textOrUndefined(url.searchParams.get("err"));

  if (!net_date || !isValidNetDate(net_date)) return redirect("/signup?err=Invalid+net+date");
  if (!roleRaw || (roleRaw !== "primary" && roleRaw !== "backup")) return redirect("/signup?err=Invalid+role");

  const role = roleRaw as NetRole;
  const weekday = await inferNetWeekday(env);
  const recurring = resolveRecurringOverride(net_date, role, weekday);
  if (recurring) {
    return redirect(`/signup?err=${encodeURIComponent(`${titleRole(role)} is pre-assigned to ${recurring.operator_callsign} for ${net_date}`)}`);
  }

  const existing = await env.DB.prepare(
    `SELECT id FROM net_signups WHERE net_date = ?1 AND role = ?2`
  ).bind(net_date, role).first();
  if (existing) {
    return redirect(`/signup?err=${encodeURIComponent(`${titleRole(role)} slot is already taken for ${net_date}`)}`);
  }

  const body = `
    <div class="card">
      <h1>Sign Up for Net Control</h1>
      <p class="muted"><strong>Date:</strong> ${escapeHtml(formatDateDisplay(net_date))} (${escapeHtml(net_date)})<br/>
      <strong>Role:</strong> ${escapeHtml(titleRole(role))}</p>
      ${err ? `<div class="err"><strong>Could not save.</strong> ${escapeHtml(err)}</div>` : ""}
      <form method="post" action="/signup/new">
        <input type="hidden" name="net_date" value="${escapeHtml(net_date)}" />
        <input type="hidden" name="role" value="${escapeHtml(role)}" />

        <label for="operator_name">Name *</label>
        <input id="operator_name" name="operator_name" required />

        <label for="operator_email">Email *</label>
        <input id="operator_email" name="operator_email" type="email" required />

        <label for="operator_callsign">Callsign *</label>
        <input id="operator_callsign" name="operator_callsign" required />

        <button class="btn" type="submit">Confirm Signup</button>
        <a class="btn btn-ghost" href="/signup">Back to Schedule</a>
      </form>
    </div>
  `;

  return new Response(HTML(body), { headers: { "content-type": "text/html; charset=utf-8" } });
}

async function handleSignupNewPOST(request: Request, env: Env) {
  const form = await request.formData();
  const net_date = textOrUndefined(form.get("net_date"));
  const roleRaw = textOrUndefined(form.get("role"));
  const operator_name = textOrUndefined(form.get("operator_name"));
  const operator_email = textOrUndefined(form.get("operator_email"));
  const operator_callsign = textOrUndefined(form.get("operator_callsign"));

  if (!net_date || !isValidNetDate(net_date)) return redirect("/signup?err=Invalid+net+date");
  if (!roleRaw || (roleRaw !== "primary" && roleRaw !== "backup")) return redirect("/signup?err=Invalid+role");

  const role = roleRaw as NetRole;
  const weekday = await inferNetWeekday(env);
  const recurring = resolveRecurringOverride(net_date, role, weekday);
  if (recurring) {
    return redirect(`/signup?err=${encodeURIComponent(`${titleRole(role)} is pre-assigned to ${recurring.operator_callsign} for ${net_date}`)}`);
  }

  if (!operator_name) return redirect(buildSignupFormUrl(net_date, role, "Name is required"));
  if (!operator_email || !isValidEmail(operator_email)) return redirect(buildSignupFormUrl(net_date, role, "Valid email is required"));
  if (!operator_callsign) return redirect(buildSignupFormUrl(net_date, role, "Callsign is required"));

  const callsign = normalizeCallsign(operator_callsign);

  const existing = await env.DB.prepare(
    `SELECT id FROM net_signups WHERE net_date = ?1 AND role = ?2`
  ).bind(net_date, role).first();

  if (existing) {
    return redirect(`/signup?err=${encodeURIComponent(`${titleRole(role)} slot is already taken for ${net_date}`)}`);
  }

  await env.DB.prepare(
    `INSERT INTO net_signups (net_date, role, operator_name, operator_email, operator_callsign)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(net_date, role, operator_name, operator_email, callsign).run();

  return redirect("/signup?ok=1");
}

async function handleSignupAdminGET(request: Request, env: Env) {
  const url = new URL(request.url);
  const err = textOrUndefined(url.searchParams.get("err"));
  const ok = textOrUndefined(url.searchParams.get("ok"));

  if (!hasSignupAdminCookie(request)) {
    const body = `
      <div class="card">
        <h1>Signup Admin</h1>
        <p class="muted">Enter admin passcode to manage net signups.</p>
        ${err ? `<div class="err"><strong>Access denied.</strong> ${escapeHtml(err)}</div>` : ""}
        <form method="post" action="/signup/admin/login">
          <label for="password">Passcode *</label>
          <input id="password" name="password" type="password" required />
          <button class="btn" type="submit">Log In</button>
          <a class="btn btn-ghost" href="/signup">Back to Schedule</a>
        </form>
      </div>
    `;
    return new Response(HTML(body), { headers: { "content-type": "text/html; charset=utf-8" } });
  }

  const { results } = await env.DB.prepare(
    `SELECT id, net_date, role, operator_name, operator_email, operator_callsign, created_at
     FROM net_signups
     ORDER BY net_date ASC, role ASC, id ASC`
  ).all();

  const rows = (results ?? [])
    .map((r: any) => `
      <tr>
        <td>${escapeHtml(String(r.net_date ?? ""))}</td>
        <td>${escapeHtml(titleRole(r.role === "backup" ? "backup" : "primary"))}</td>
        <td>${escapeHtml(String(r.operator_callsign ?? ""))}</td>
        <td>${escapeHtml(String(r.operator_name ?? ""))}</td>
        <td>${escapeHtml(String(r.operator_email ?? ""))}</td>
        <td>${escapeHtml(String(r.created_at ?? ""))}</td>
        <td>
          <form method="post" action="/signup/admin/delete" onsubmit="return confirm('Delete this registration?');">
            <input type="hidden" name="id" value="${escapeHtml(String(r.id ?? ""))}" />
            <button class="btn" type="submit">Delete</button>
          </form>
        </td>
      </tr>
    `)
    .join("");

  const body = `
    <div class="card">
      <h1>Signup Admin</h1>
      <p class="muted">Manage net signup registrations.</p>
      ${ok ? `<div class="ok"><strong>Success.</strong> ${escapeHtml(ok)}</div>` : ""}
      ${err ? `<div class="err"><strong>Error.</strong> ${escapeHtml(err)}</div>` : ""}
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>Role</th>
            <th>Callsign</th>
            <th>Name</th>
            <th>Email</th>
            <th>Created</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>${rows || `<tr><td colspan="7">No signups yet.</td></tr>`}</tbody>
      </table>
      <p class="row">
        <form method="post" action="/signup/admin/logout">
          <button class="btn btn-ghost" type="submit">Log Out</button>
        </form>
        <a class="btn btn-ghost" href="/signup">Back to Schedule</a>
      </p>
    </div>
  `;
  return new Response(HTML(body), { headers: { "content-type": "text/html; charset=utf-8" } });
}

async function handleSignupAdminLoginPOST(request: Request, env: Env) {
  const form = await request.formData();
  const password = textOrUndefined(form.get("password"));
  if (!requireAuth(password, env)) return redirect("/signup/admin?err=Invalid+passcode");

  const res = redirect("/signup/admin");
  res.headers.append("set-cookie", signupAdminCookie());
  return res;
}

async function handleSignupAdminLogoutPOST() {
  const res = redirect("/signup/admin");
  res.headers.append("set-cookie", clearSignupAdminCookie());
  return res;
}

async function handleSignupAdminDeletePOST(request: Request, env: Env) {
  if (!hasSignupAdminCookie(request)) return redirect("/signup/admin?err=Not+authorized");

  const form = await request.formData();
  const idRaw = textOrUndefined(form.get("id"));
  const id = Number(idRaw);
  if (!idRaw || !Number.isFinite(id) || id <= 0) return redirect("/signup/admin?err=Invalid+signup+id");

  const result = await env.DB.prepare(`DELETE FROM net_signups WHERE id = ?1`).bind(id).run();
  const changed = (result as any)?.meta?.changes ?? 0;
  if (!changed) return redirect("/signup/admin?err=Signup+not+found");

  return redirect("/signup/admin?ok=Registration+deleted");
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
      <p class="row">
        <a class="btn btn-ghost" href="/signup">Net Sign Up</a>
        <a class="btn btn-ghost" href="/submit">Submit Net Log</a>
      </p>
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
  const net = row as Record<string, unknown>;

  const body = `
    <div class="card">
      <h1>Net Details — ${String(net.net_date ?? "")}</h1>
      <p class="muted">Entry #${String(net.id ?? "")} • Created ${escapeHtml(String(net.created_at ?? ""))}</p>
      <div class="grid-2">
        <div>
          <label>Net Control (Callsign)</label>
          <input readonly value="${escapeHtml(String(net.net_control_callsign ?? ""))}"/>
        </div>
        <div>
          <label>Net Control (Name)</label>
          <input readonly value="${escapeHtml(String(net.net_control_name ?? ""))}"/>
        </div>
      </div>
      <div style="margin-top:10px;">
        <label># of Check-ins</label>
        <input readonly value="${String(net.check_ins_count ?? 0)}"/>
      </div>

      <div style="margin-top:14px;">
        <label>Check-ins List</label>
        <div class="card" style="padding:12px; margin-top:4px;">
          <div class="mono">${escapeHtml(String(net.check_ins_list ?? ""))}</div>
        </div>
      </div>

      <div style="margin-top:14px;">
        <label>Comments</label>
        <div class="card" style="padding:12px; margin-top:4px;">
          <div class="mono">${escapeHtml(String(net.comments ?? ""))}</div>
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
    last_check_ins: (last as any)?.check_ins_count ?? null,
    last_date: (last as any)?.net_date ?? null,
    avg_90d: round2((avg90 as any)?.avg),
    avg_180d: round2((avg180 as any)?.avg),
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

export default Sentry.withSentry(
  (env: Env) => ({
    dsn: env.SENTRY_DSN,                // from secret
    tracesSampleRate: 1.0,              // capture 100% of traces; tune in prod
    enableLogs: true,                   // forward CF logs to Sentry
    sendDefaultPii: true,               // captures IP and similar PII
    environment: env.SENTRY_ENVIRONMENT || "production",
    release: env.SENTRY_RELEASE,        // optional, improves source map linking
    integrations: [],                   // (optional) add custom integrations here
  }),
  {
    async fetch(request: Request, env: Env, ctx) {
      // Helpful: add some request context for every event
      Sentry.setTag("cf.worker", "w4trc-net-logging");
      Sentry.setTag("request.method", request.method);
      Sentry.setTag("request.urlpath", new URL(request.url).pathname);

      try {
        const url = new URL(request.url);
        const { pathname } = url;

        if (pathname === "/" || pathname === "") return handleHome();

        if (pathname === "/submit" && request.method === "GET") return handleSubmitGET(env);
        if (pathname === "/submit" && request.method === "POST") return handleSubmitPOST(request, env);

        if (pathname === "/signup" && request.method === "GET") return handleSignupGET(request, env);
        if (pathname === "/signup/new" && request.method === "GET") return handleSignupNewGET(request, env);
        if (pathname === "/signup/new" && request.method === "POST") return handleSignupNewPOST(request, env);
        if (pathname === "/signup/admin" && request.method === "GET") return handleSignupAdminGET(request, env);
        if (pathname === "/signup/admin/login" && request.method === "POST") return handleSignupAdminLoginPOST(request, env);
        if (pathname === "/signup/admin/logout" && request.method === "POST") return handleSignupAdminLogoutPOST();
        if (pathname === "/signup/admin/delete" && request.method === "POST") return handleSignupAdminDeletePOST(request, env);

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
              "access-control-allow-headers": "content-type",
            },
          });
        }

        return new Response("Not Found", { status: 404 });
      } catch (err) {
        // Capture and return a safe response
        Sentry.captureException(err);
        return new Response("Internal Error", { status: 500 });
      }
    },
  } satisfies ExportedHandler<Env>,
);
