import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Cable, ChevronDown, KeyRound, LogOut, Moon, PlugZap, ShieldCheck, Sun, Trash2 } from "lucide-react";
import "./index.css";

const formBody = (values) => new URLSearchParams(values);

async function submit(path, values) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: formBody(values) });
  if (!response.ok) throw new Error((await response.text()) || `Request failed (${response.status})`);
}

function Shell({ children, signedIn, onSignOut, signingOut }) {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  function toggleTheme() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("cog-theme", next ? "dark" : "light");
    document.querySelector('meta[name="theme-color"]').content = next ? "#09090b" : "#fafafa";
  }
  return <main className="mx-auto min-h-screen max-w-7xl px-5 py-8 sm:px-8">
    <header className="mb-8 flex items-center gap-3"><div className="grid size-10 place-items-center rounded-xl bg-blue-500 text-white shadow-lg shadow-blue-500/25"><Cable size={21}/></div><div><div className="text-lg font-bold tracking-tight">COG</div><div className="text-xs text-zinc-500 dark:text-zinc-400">Clanker Operations Gateway</div></div><div className="ml-auto flex items-center gap-2">{signedIn && <button className="button-secondary" disabled={signingOut} onClick={onSignOut}><LogOut size={16}/> Sign out</button>}<button className="icon-button" onClick={toggleTheme} aria-label={`Use ${dark ? "light" : "dark"} mode`} title={`Use ${dark ? "light" : "dark"} mode`}>{dark ? <Sun size={17}/> : <Moon size={17}/>}</button></div></header>
    {children}
  </main>;
}

function AuthCard({ mode, reload }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function handle(event) {
    event.preventDefault(); setBusy(true); setError("");
    const values = Object.fromEntries(new FormData(event.currentTarget));
    try { await submit("/login", values); await reload(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  }
  return <div className="grid min-h-[70vh] place-items-center"><section className="card w-full max-w-md p-7 sm:p-9">
    <p className="eyebrow">Welcome back</p><h1 className="mt-3 text-3xl font-bold tracking-tight">Sign in to COG</h1>
    <p className="mt-3 text-sm leading-6 text-zinc-600 dark:text-zinc-400">Manage integrations, clients, and active agent credentials.</p>
    <form className="mt-7 space-y-4" onSubmit={handle}><label className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Email<input className="input mt-2" name="email" type="email" autoComplete="email" required/></label><label className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Password<input className="input mt-2" name="password" type="password" autoComplete="current-password" required/></label>{error && <p className="rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-500/10 dark:text-red-300">{error}</p>}<button className="button w-full" disabled={busy}>{busy ? "Please wait…" : "Sign in"}</button></form>
  </section></div>;
}

function Empty({ children }) { return <div className="rounded-xl border border-dashed border-zinc-200 py-10 text-center text-sm text-zinc-500 dark:border-white/10 dark:text-zinc-400">{children}</div>; }

const fullDate = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const relativeDate = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
function tokenTime(timestamp) {
  const date = new Date(timestamp * 1000);
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const units = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
  const [unit, size] = units.find(([, size]) => Math.abs(seconds) >= size) || units.at(-1);
  return { exact: fullDate.format(date), relative: relativeDate.format(Math.round(seconds / size), unit) };
}

function TokenDate({ label, timestamp }) {
  const value = tokenTime(timestamp);
  return <span title={value.exact}><span className="text-zinc-500 dark:text-zinc-400">{label}</span> {value.relative} <span className="text-zinc-400 dark:text-zinc-500">· {value.exact}</span></span>;
}

function Pills({ values, empty = "none" }) {
  return <div className="flex flex-wrap gap-1.5">{values.length ? values.map(value => <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs text-zinc-600 dark:bg-white/5 dark:text-zinc-300" key={value}>{value}</span>) : <span className="text-xs text-zinc-400 dark:text-zinc-500">{empty}</span>}</div>;
}

function AgentAccess({ data, action, busy, integrationLabel }) {
  const [expanded, setExpanded] = useState(() => new Set());
  function toggle(clientId) {
    setExpanded(current => {
      const next = new Set(current);
      next.has(clientId) ? next.delete(clientId) : next.add(clientId);
      return next;
    });
  }
  const orphanTokens = data.tokens.filter(token => !data.clients.some(client => client.client_id === token.client_id));
  const Token = ({ item }) => <div className="rounded-xl border border-zinc-200 bg-white p-3 dark:border-white/8 dark:bg-black/20">
    <div className="flex items-start gap-3"><div className="grid size-8 shrink-0 place-items-center rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-300"><KeyRound size={15}/></div><div className="min-w-0 flex-1"><div className="flex items-center justify-between gap-2"><div><div className="text-sm font-medium">Issued credential</div><code className="block max-w-52 truncate text-xs text-zinc-400 dark:text-zinc-500">{item.token_id}</code></div><button aria-label={`Revoke token ${item.token_id}`} title="Revoke this credential" className="button-danger" disabled={!!busy} onClick={() => action(`/ui/tokens/${item.token_id}/revoke`, {})}><Trash2 size={14}/></button></div><div className="mt-2 grid gap-1 text-xs sm:grid-cols-2"><TokenDate label="Issued" timestamp={item.issued_at}/><TokenDate label="Access expires" timestamp={item.expires_at}/>{item.last_used_at && <TokenDate label="Last used" timestamp={item.last_used_at}/>} {item.refresh_expires_at && <TokenDate label="Refresh expires" timestamp={item.refresh_expires_at}/>}</div><div className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">{item.refresh_capable ? "Refresh credential available" : "No refresh credential"}</div></div></div>
  </div>;
  return <section className="card overflow-hidden"><div className="border-b border-zinc-200 px-4 py-3 dark:border-white/8"><h2 className="font-semibold">Agents</h2><p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">Approved applications and their access.</p></div>
    {data.clients.length === 0 ? <div className="p-4"><Empty>No authorized agents.</Empty></div> : <div className="overflow-x-auto"><table className="compact-table"><thead><tr><th>Agent</th><th>Scopes</th><th>Integrations</th><th>Credentials</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{data.clients.map(client => {
      const tokens = data.tokens.filter(token => token.client_id === client.client_id);
      const scopes = client.scopes.filter(scope => !scope.startsWith("integration:"));
      const available = data.integrations.filter(item => !client.integration_ids.includes(item.id));
      const open = expanded.has(client.client_id);
      return <React.Fragment key={client.client_id}><tr><td><div className="font-medium">{client.client_name}</div><code className="block max-w-56 truncate text-[11px] text-zinc-400 dark:text-zinc-500">{client.client_id}</code></td><td><Pills values={scopes}/></td><td><div className="flex min-w-40 flex-wrap gap-1.5">{client.integration_ids.map(id => <button type="button" className="table-pill" title="Revoke this integration grant" key={id} onClick={() => action(`/ui/clients/${client.client_id}/integrations/${id}/revoke`, {})}>{integrationLabel(id)} ×</button>)}{available.map(item => <button type="button" className="table-pill-add" disabled={!!busy} key={item.id} onClick={() => action(`/ui/clients/${client.client_id}/integrations/${item.id}/grant`, {})}>+ {item.name}</button>)}</div></td><td><button type="button" className="credential-toggle" aria-expanded={open} onClick={() => toggle(client.client_id)}><KeyRound size={14}/>{tokens.length}<ChevronDown className={`transition ${open ? "rotate-180" : ""}`} size={14}/></button></td><td className="text-right"><button aria-label={`Revoke ${client.client_name}`} title="Revoke agent and all credentials" className="button-danger" disabled={!!busy} onClick={() => action(`/ui/clients/${client.client_id}/revoke`, {})}><Trash2 size={15}/></button></td></tr>{open && <tr><td className="credential-cell" colSpan="5"><div className="space-y-2">{tokens.length ? tokens.map(token => <Token item={token} key={token.token_id}/>) : <p className="text-xs text-zinc-400 dark:text-zinc-500">No active credential records.</p>}</div></td></tr>}</React.Fragment>;
    })}</tbody></table></div>}{orphanTokens.length > 0 && <div className="border-t border-amber-200 bg-amber-50 p-4 dark:border-amber-500/20 dark:bg-amber-500/10"><div className="mb-2 text-sm font-medium text-amber-800 dark:text-amber-200">Credentials whose agent record is no longer present</div><div className="grid gap-2 lg:grid-cols-2">{orphanTokens.map(token => <Token item={token} key={token.token_id}/>)}</div></div>}
  </section>;
}

function GitAccess({ data, action, busy }) {
  const grants = data.git_grants || [];
  return <section className="card overflow-hidden"><div className="border-b border-zinc-200 px-4 py-3 dark:border-white/8"><h2 className="font-semibold">Git repository grants</h2><p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">Exact repository access by OAuth client.</p></div>{grants.length === 0 ? <div className="p-4"><Empty>No Git repositories approved.</Empty></div> : <div className="overflow-x-auto"><table className="compact-table"><thead><tr><th>Repository</th><th>Agent</th><th>Permission</th><th>Last use</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{grants.map(grant => <tr key={`${grant.client_id}:${grant.repository_id}`}><td><div className="font-medium">{grant.display_name}</div><code className="text-[11px] text-zinc-400">{grant.repository_id}</code></td><td>{grant.client_name}</td><td><select className="input py-1" value={grant.permission} disabled={!!busy} onChange={event => action(`/ui/clients/${grant.client_id}/git/${grant.repository_id}/${event.target.value}`, {})}><option value="read">read</option><option value="write">write</option></select></td><td>{grant.last_used_at ? <TokenDate label="" timestamp={grant.last_used_at}/> : "Never"}</td><td className="text-right"><button className="button-danger" title="Revoke repository grant" disabled={!!busy} onClick={() => action(`/ui/clients/${grant.client_id}/git/${grant.repository_id}/revoked`, {})}><Trash2 size={15}/></button></td></tr>)}</tbody></table></div>}</section>;
}

function Dashboard({ data, reload }) {
  const [error, setError] = useState(""); const [busy, setBusy] = useState("");
  const [expandedIntegration, setExpandedIntegration] = useState("");
  const integrationLabel = (id) => data.integrations.find(item => item.id === id)?.name || id;
  async function action(path, values) { setBusy(path); setError(""); try { await submit(path, { ...values, csrf_token: data.csrf_token }); await reload(); } catch (e) { setError(e.message); } finally { setBusy(""); } }
  return <>{error && <div className="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">{error}</div>}
    <div className="grid gap-5">
      <section className="card overflow-hidden"><div className="border-b border-zinc-200 px-4 py-3 dark:border-white/8"><h2 className="font-semibold">Integrations</h2><p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">Upstream MCP servers available to agents.</p></div>
        {data.integrations.length === 0 ? <div className="p-4"><Empty>No integrations yet.</Empty></div> : <div className="overflow-x-auto"><table className="compact-table"><thead><tr><th>Name</th><th>Transport</th><th>Connection</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{data.integrations.map(item => {
          const open = expandedIntegration === item.id;
          return <React.Fragment key={item.id}><tr className="integration-row" onClick={() => setExpandedIntegration(open ? "" : item.id)}><td className="font-medium"><button type="button" className="integration-toggle" aria-expanded={open}><ChevronDown className={`transition ${open ? "rotate-180" : ""}`} size={15}/>{item.name}</button></td><td>{item.transport}</td><td><span className={item.oauth === "connected" ? "status-connected" : "status-pending"}>{item.oauth}</span></td><td className="text-right"><div className="flex justify-end gap-2"><button aria-label={`Disconnect provider for ${item.name}`} title="Disconnect provider; preserve configuration and agent grants" className="button-secondary" disabled={!!busy || item.oauth !== "connected"} onClick={(event) => { event.stopPropagation(); if (window.confirm(`Disconnect provider for ${item.name}? The integration configuration, immutable ID, and agent grants will be preserved.`)) action(`/ui/integrations/${item.id}/disconnect`, {}); }}><PlugZap size={15}/></button><button aria-label={`Delete ${item.name}`} title="Permanently delete integration and grants" className="button-danger" disabled={!!busy} onClick={(event) => { event.stopPropagation(); if (window.confirm(`Permanently delete ${item.name}? Its immutable ID, provider credentials, and all agent grants will be lost.`)) action(`/ui/integrations/${item.id}/delete`, {}); }}><Trash2 size={15}/></button></div></td></tr>{open && <tr><td className="integration-detail-cell" colSpan="4"><div className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Granted OAuth scopes</div><div className="mt-2"><Pills values={item.oauth_scopes || []} empty={item.oauth === "connected" ? "No scopes were returned by the authorization server." : "Connect this integration to see its granted scopes."}/></div></td></tr>}</React.Fragment>;
        })}</tbody></table></div>}
      </section>
      <AgentAccess data={data} action={action} busy={busy} integrationLabel={integrationLabel}/>
      <GitAccess data={data} action={action} busy={busy}/>
    </div><footer className="mt-8 flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-500"><ShieldCheck size={14}/> Credentials are encrypted at rest and never displayed here.</footer></>;
}

function App() { const [data, setData] = useState(null); const [error, setError] = useState(""); const [signingOut, setSigningOut] = useState(false); async function load() { setError(""); try { const r = await fetch("/api/ui"); if (!r.ok) throw new Error("Unable to load COG"); setData(await r.json()); } catch (e) { setError(e.message); } } async function signOut() { setSigningOut(true); setError(""); try { await submit("/logout", { csrf_token: data.csrf_token }); await load(); } catch (e) { setError(e.message); } finally { setSigningOut(false); } } useEffect(() => { load(); }, []); return <Shell signedIn={data?.mode === "admin"} onSignOut={signOut} signingOut={signingOut}>{error ? <div className="card p-6 text-red-700 dark:text-red-300">{error}</div> : !data ? <div className="grid min-h-[60vh] place-items-center text-sm text-zinc-500">Loading COG…</div> : data.mode === "admin" ? <Dashboard data={data} reload={load}/> : <AuthCard mode={data.mode} reload={load}/>}</Shell>; }

createRoot(document.getElementById("root")).render(<React.StrictMode><App/></React.StrictMode>);
