"use strict";
// Admin SPA. All data is rendered with textContent / DOM nodes (never innerHTML).
const base = new URL(document.baseURI).pathname;
let csrf = "", S = null; // state
const $ = (s, r = document) => r.querySelector(s);

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}

async function api(path, body) {
  const opt = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opt.method = "POST";
    opt.headers = { "Content-Type": "application/json", "X-CSRF-Token": csrf };
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(base + "api/" + path, opt);
  let data = {};
  try { data = await r.json(); } catch (_) { /* non-JSON */ }
  if (r.status === 401 && path !== "login") { showLogin(); throw new Error("signed out"); }
  return { ok: r.ok, status: r.status, data };
}

function banner(kind, text) {
  const b = h("div", { class: "banner " + kind, role: "status" }, text);
  return b;
}
function flash(container, kind, text) {
  const old = $(".banner.flash", container); if (old) old.remove();
  const b = banner(kind, text); b.classList.add("flash"); container.prepend(b);
  if (kind === "ok") setTimeout(() => b.remove(), 5000);
}

// ---- login ----
async function boot() {
  const { data } = await api("session");
  if (data.authenticated) { csrf = data.csrf; return loadApp(); }
  showLogin(data.configured === false);
}
function showLogin(unconfigured) {
  $("#logout").hidden = true;
  const pw = h("input", { type: "password", id: "pw", autocomplete: "current-password", autofocus: true });
  const msg = h("div");
  const go = async () => {
    const { ok, data } = await api("login", { password: pw.value });
    if (ok) { csrf = data.csrf; loadApp(); } else flash(msg, "err", data.message || "Sign-in failed");
  };
  pw.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  $("#app").replaceChildren(h("div", { class: "card" }, h("h2", {}, "Sign in"), msg,
    unconfigured ? banner("warn", "No admin password is set yet. Run `zabbix-mcp set-admin-password` on the server.") : null,
    h("label", { for: "pw" }, "Admin password"), pw,
    h("div", { class: "row" }, h("button", { class: "primary", onclick: go }, "Sign in"))));
}
$("#logout").addEventListener("click", async () => { await api("logout", {}); csrf = ""; showLogin(); });

// ---- app shell ----
const TABS = ["Connection", "Safety", "Access", "Server", "Audit log"];
let tab = "Connection";
async function loadApp() {
  const { data } = await api("state");
  S = data; $("#ver").textContent = "v" + data.version; $("#logout").hidden = false;
  render();
}
function render() {
  const nav = h("nav", { role: "tablist" }, TABS.map((t) =>
    h("button", { role: "tab", "aria-selected": t === tab, onclick: () => { tab = t; render(); } }, t)));
  const body = h("div");
  $("#app").replaceChildren(nav, body);
  ({ Connection: tabConnection, Safety: tabSafety, Access: tabAccess, Server: tabServer, "Audit log": tabAudit })[tab](body);
}

// ---- form helpers ----
function text(id, label, value, opts = {}) {
  return [h("label", { for: id }, label),
    h("input", { type: opts.password ? "password" : (opts.number ? "number" : "text"), id, value: value ?? "",
      placeholder: opts.placeholder || "", autocomplete: "off" }),
    opts.hint ? h("p", { class: "hint" }, opts.hint) : null];
}
function check(id, label, on, hint) {
  return [h("label", { class: "inline" }, h("input", { type: "checkbox", id, checked: !!on }), label),
    hint ? h("p", { class: "hint" }, hint) : null];
}
const val = (id) => { const e = $("#" + id); return e.type === "checkbox" ? e.checked : e.value; };
const lines = (id) => val(id).split("\n").map((x) => x.trim()).filter(Boolean);
async function save(container, changes, extra) {
  const { ok, data } = await api("settings", { changes });
  if (!ok) return flash(container, "err", data.message || "Save failed");
  S.settings = data.settings;
  flash(container, data.restart_required ? "warn" : "ok",
    data.restart_required ? "Saved. Restart the server (Server tab) for this change to take effect." : "Saved and applied.");
  if (extra) extra();
}

// ---- tabs ----
function tabConnection(root) {
  const s = S.settings, c = h("div", { class: "card" });
  c.append(h("h2", {}, "Zabbix connection"),
    ...text("zabbix_url", "Zabbix URL", s.zabbix_url, { placeholder: "https://zabbix.example.com", hint: "The Zabbix web frontend address (the /api_jsonrpc.php part is added automatically)." }),
    ...text("zabbix_api_token", "API token", "", { password: true, placeholder: s.zabbix_api_token ? "•••••••• (set — leave blank to keep)" : "paste token", hint: "Use a token created for a dedicated API-only user. It is never shown again." }),
    ...check("verify_tls", "Verify TLS certificate", s.verify_tls),
    ...text("ca_bundle", "CA bundle path (optional)", s.ca_bundle, { hint: "For a private CA, a path inside the container." }),
    h("h3", {}, "Legacy fallback (optional)"),
    ...text("zabbix_user", "Username", s.zabbix_user, { hint: "Only used when no API token is set." }),
    ...text("zabbix_password", "Password", "", { password: true, placeholder: s.zabbix_password ? "•••••••• (set)" : "" }));
  const out = h("div");
  c.append(out, h("div", { class: "row" },
    h("button", { onclick: async () => {
      out.replaceChildren(h("p", { class: "muted" }, "Testing…"));
      const { data } = await api("test-connection", { candidate: { zabbix_url: val("zabbix_url"), zabbix_api_token: val("zabbix_api_token"), verify_tls: val("verify_tls"), ca_bundle: val("ca_bundle"), zabbix_user: val("zabbix_user"), zabbix_password: val("zabbix_password") } });
      out.replaceChildren(data.ok ? banner(data.supported ? "ok" : "warn", `Connected to Zabbix ${data.version}` + (data.supported ? "" : " — this server targets 7.4; some features may differ") + (data.can_read_hosts ? ", token can read hosts." : "."))
        : banner("err", (data.message || "Failed") + (data.hint ? " — " + data.hint : "")));
    } }, "Test connection"),
    h("button", { class: "primary", onclick: () => save(c, { zabbix_url: val("zabbix_url"), zabbix_api_token: val("zabbix_api_token"), verify_tls: val("verify_tls"), ca_bundle: val("ca_bundle"), zabbix_user: val("zabbix_user"), zabbix_password: val("zabbix_password") }) }, "Save")));
  root.append(c);
}

function tabSafety(root) {
  const s = S.settings, c = h("div", { class: "card" });
  const ro = check("read_only", "Read-only mode (block every change to Zabbix)", s.read_only, "Turn off to let agents create, update and delete objects. Changes still need confirmation per the setting below.");
  const sel = h("select", { id: "confirm_writes" }, [["all", "Confirm every write (recommended)"], ["destructive", "Confirm only destructive writes (delete, clear, mass remove…)"], ["none", "No confirmation (not recommended)"]].map(([v, t]) => h("option", { value: v, selected: s.confirm_writes === v }, t)));
  c.append(h("h2", {}, "Safety"), ...ro, h("label", { for: "confirm_writes" }, "Write confirmation"), sel,
    h("p", { class: "hint" }, "With confirmation, an agent first gets a preview and a single-use token that expires in 5 minutes."),
    h("h3", {}, "Enabled toolsets"));
  const grid = h("div", { class: "grid" });
  for (const [name, groups] of Object.entries(S.toolsets)) {
    grid.append(h("label", { class: "inline", title: groups.join(", ") }, h("input", { type: "checkbox", "data-ts": name, checked: s.toolsets.includes(name) }), name + (name === "admin" ? " (users, tokens, settings — high risk)" : "")));
  }
  c.append(grid, h("p", { class: "hint" }, "A toolset is a tool covering several related API groups. Curated tools and zabbix_raw_api are always available. Changing toolsets needs a restart."),
    h("h3", {}, "Blocked by default"),
    h("p", { class: "hint" }, S.default_blocked.join(", ")),
    h("label", { for: "allow_methods" }, "Allow list (one pattern per line, e.g. user.create)"),
    h("textarea", { id: "allow_methods" }, s.allow_methods.join("\n")),
    h("label", { for: "deny_methods" }, "Deny list (always blocked, wins over allow; e.g. host.delete or item.*)"),
    h("textarea", { id: "deny_methods" }, s.deny_methods.join("\n")),
    h("div", { class: "row" }, h("button", { class: "primary", onclick: () => save(c, { read_only: val("read_only"), confirm_writes: val("confirm_writes"), toolsets: [...c.querySelectorAll("[data-ts]")].filter((e) => e.checked).map((e) => e.dataset.ts), allow_methods: lines("allow_methods"), deny_methods: lines("deny_methods") }) }, "Save")));
  root.append(c);
}

function tabAccess(root) {
  const s = S.settings, c = h("div", { class: "card" }), list = h("div"), shown = h("div");
  c.append(h("h2", {}, "Client access"),
    ...text("public_url", "Public URL of this server", s.public_url, { placeholder: "https://example.com/zabbix-mcp", hint: "Where agents reach it (including any path prefix). Used to show the endpoint below." }),
    h("div", { class: "row" }, h("button", { class: "primary", onclick: () => save(c, { public_url: val("public_url") }, loadApp) }, "Save")),
    h("h3", {}, "Endpoint"), h("pre", {}, S.endpoint || "(set the public URL above)"),
    h("h3", {}, "Access tokens"), h("p", { class: "hint" }, "Agents send a token as “Authorization: Bearer …”. Only a hash is stored; a new token is shown once."), shown, list,
    h("div", { class: "row" }, h("button", { onclick: async () => {
      const { data } = await api("tokens", { action: "create" });
      shown.replaceChildren(banner("warn", "Copy this token now — it will not be shown again."), h("pre", {}, data.token),
        h("pre", {}, JSON.stringify({ mcpServers: { zabbix: { url: S.endpoint || "https://HOST/zabbix-mcp/mcp", headers: { Authorization: "Bearer " + data.token } } } }, null, 2)));
      const st = await api("state"); S = st.data; drawTokens();
    } }, "Create token")));
  function drawTokens() {
    list.replaceChildren(h("table", {}, h("tbody", {}, S.tokens.length ? S.tokens.map((fp) => h("tr", {}, h("td", {}, h("code", {}, fp + "…")), h("td", {}, h("button", { class: "danger", onclick: async () => {
      if (!confirm("Revoke this token? Agents using it lose access immediately.")) return;
      await api("tokens", { action: "revoke", fingerprint: fp }); const st = await api("state"); S = st.data; drawTokens();
    } }, "Revoke")))) : h("tr", {}, h("td", { class: "muted" }, "No tokens — HTTP clients cannot connect.")))));
  }
  drawTokens(); root.append(c);
}

function tabServer(root) {
  const s = S.settings, c = h("div", { class: "card" });
  c.append(h("h2", {}, "Server"),
    ...text("request_timeout", "Zabbix request timeout (seconds)", s.request_timeout, { number: true }),
    ...text("default_limit", "Default result limit for list calls", s.default_limit, { number: true, hint: "Keeps responses small for the model." }),
    ...text("max_response_chars", "Max response size (characters)", s.max_response_chars, { number: true }),
    h("label", { for: "log_level" }, "Log level"),
    h("select", { id: "log_level" }, ["DEBUG", "INFO", "WARNING", "ERROR"].map((l) => h("option", { value: l, selected: s.log_level === l }, l))),
    ...text("audit_log", "Audit log file", s.audit_log, { hint: "Every Zabbix call is logged as one JSON line (secrets masked). Leave empty to log to the container log." }),
    h("div", { class: "row" },
      h("button", { class: "primary", onclick: () => save(c, { request_timeout: +val("request_timeout"), default_limit: +val("default_limit"), max_response_chars: +val("max_response_chars"), log_level: val("log_level"), audit_log: val("audit_log") }) }, "Save"),
      h("button", { onclick: async () => { if (!confirm("Restart the server now?")) return; await api("restart", {}); flash(c, "warn", "Restarting… reload this page in a few seconds."); } }, "Restart server")));
  const p = h("div", { class: "card" });
  p.append(h("h2", {}, "Admin password"), ...text("pw_cur", "Current password", "", { password: true }), ...text("pw_new", "New password (min 12 characters)", "", { password: true }),
    h("div", { class: "row" }, h("button", { onclick: async () => {
      const { ok, data } = await api("password", { current: val("pw_cur"), new: val("pw_new") });
      flash(p, ok ? "ok" : "err", ok ? "Password changed." : data.message || "Failed");
    } }, "Change password")));
  root.append(c, p);
}

function tabAudit(root) {
  const c = h("div", { class: "card" }), out = h("div");
  const load = async () => {
    const { data } = await api("audit");
    if (!data.configured) return out.replaceChildren(banner("warn", "No audit log file configured (Server tab). Entries go to the container log."));
    const rows = data.lines.map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean).reverse();
    out.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Method", "Result", "ms"].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, h("td", {}, new Date(r.ts * 1000).toLocaleString()),
        h("td", {}, h("code", {}, r.method), r.mutating ? h("span", { class: "tag" }, "write") : null),
        h("td", {}, h("span", { class: "tag " + (r.outcome === "ok" ? "good" : "bad") }, r.outcome)), h("td", {}, r.ms))))));
  };
  c.append(h("h2", {}, "Recent Zabbix calls"), h("div", { class: "row" }, h("button", { onclick: load }, "Refresh")), out);
  root.append(c); load();
}

boot();
