import React, { useState } from "react";
import { ChevronDown, KeyRound, PlugZap, ShieldCheck, Trash2, Users } from "lucide-react";
import { submit } from "../api";
import Pills from "../components/Pills";

const short = (id) => id?.slice(0, 8) || "";

export default function Dashboard({ data, reload }) {
  const [open, setOpen] = useState(new Set());
  const [error, setError] = useState("");
  async function act(path, v = {}) {
    try {
      await submit(path, { ...v, csrf_token: data.csrf_token });
      reload();
    } catch (x) {
      setError(x.message);
    }
  }
  function toggle(id) {
    setOpen((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }
  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-xl bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}
      <div className="flex items-end justify-between">
        <div>
          <p className="eyebrow">Access profiles</p>
          <h1 className="mt-2 text-3xl font-bold">Identities</h1>
          <p className="mt-2 text-sm text-zinc-500">
            Each identity has its own provider persona, connections, agents, and
            shared permissions.
          </p>
        </div>
        <button
          className="button"
          onClick={() => {
            const name = prompt("Identity name");
            if (name) act("/ui/identities", { name });
          }}
        >
          Create identity
        </button>
      </div>
      {!data.identities?.length ? (
        <section className="card p-10 text-center">
          <Users className="mx-auto text-blue-500" />
          <h2 className="mt-4 font-semibold">Create your first identity</h2>
          <p className="mt-2 text-sm text-zinc-500">
            Identities separate provider accounts and access policies.
          </p>
        </section>
      ) : (
        data.identities.map((identity) => {
          const expanded = open.has(identity.id);
          const tokens = data.tokens.filter((t) =>
            identity.agents.some((a) => a.oauth_client_id === t.client_id),
          );
          return (
            <section className="card overflow-hidden" key={identity.id}>
              <div className="flex items-center gap-3 border-b border-zinc-200 p-4 dark:border-white/10">
                <button
                  className="icon-button"
                  onClick={() => toggle(identity.id)}
                >
                  <ChevronDown className={expanded ? "rotate-180" : ""} />
                </button>
                <div>
                  <h2 className="font-semibold">{identity.name}</h2>
                  <code className="text-[11px] text-zinc-400">
                    {short(identity.id)}
                  </code>
                </div>
                <div className="ml-auto text-xs text-zinc-500">
                  {identity.connections.length} connections ·{" "}
                  {identity.agents.length} agents
                </div>
                <button
                  className="button-secondary"
                  onClick={() => {
                    const name = prompt("Rename identity", identity.name);
                    if (name)
                      act(`/ui/identities/${identity.id}/rename`, { name });
                  }}
                >
                  Rename
                </button>
                <button
                  className="button-danger"
                  onClick={() =>
                    confirm(
                      `Delete ${identity.name} and all of its connections, agents, credentials, and grants?`,
                    ) && act(`/ui/identities/${identity.id}/delete`)
                  }
                >
                  <Trash2 size={15} />
                </button>
              </div>
              {expanded && (
                <div className="grid gap-5 p-4 lg:grid-cols-3">
                  <div>
                    <h3 className="mb-3 font-semibold">Connections</h3>
                    {identity.connections.length ? (
                      identity.connections.map((c) => (
                        <div
                          className="mb-2 rounded-xl border border-zinc-200 p-3 dark:border-white/10"
                          key={c.id}
                        >
                          <div className="font-medium">{c.display_name}</div>
                          <div className="text-xs text-zinc-500">
                            {c.transport} · {c.oauth}
                          </div>
                          {(c.provider_name || c.provider_account) && (
                            <div className="mt-1 text-xs text-zinc-400">
                              {[c.provider_name, c.provider_account]
                                .filter(Boolean)
                                .join(" · ")}
                            </div>
                          )}
                          <Pills values={c.oauth_scopes} />
                          <div className="mt-2 flex gap-2">
                            <button
                              className="button-secondary"
                              onClick={() =>
                                confirm(
                                  "Disconnect credentials but preserve this connection?",
                                ) && act(`/ui/integrations/${c.id}/disconnect`)
                              }
                            >
                              <PlugZap size={14} />
                            </button>
                            <button
                              className="button-danger"
                              onClick={() =>
                                confirm(
                                  "Delete this connection and every descendant?",
                                ) && act(`/ui/integrations/${c.id}/delete`)
                              }
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-zinc-400">No connections.</p>
                    )}
                  </div>
                  <div>
                    <h3 className="mb-3 font-semibold">Agents</h3>
                    {identity.agents.length ? (
                      identity.agents.map((a) => (
                        <div
                          className="mb-2 rounded-xl border border-zinc-200 p-3 dark:border-white/10"
                          key={a.id}
                        >
                          <div className="font-medium">{a.display_name}</div>
                          <code className="text-[11px] text-zinc-400">
                            agent {short(a.id)} · client{" "}
                            {short(a.oauth_client_id)}
                          </code>
                          {a.registered_name !== a.display_name && (
                            <div className="text-xs text-zinc-500">
                              Registered as {a.registered_name}
                            </div>
                          )}
                          <div className="mt-2 flex items-center justify-between text-xs text-zinc-500">
                            <span>
                              <KeyRound className="inline" size={13} />{" "}
                              {
                                tokens.filter(
                                  (t) => t.client_id === a.oauth_client_id,
                                ).length
                              }{" "}
                              credentials
                            </span>
                            <button
                              className="button-secondary"
                              onClick={() => {
                                const name = prompt(
                                  "Rename agent",
                                  a.display_name,
                                );
                                if (name)
                                  act(`/ui/agents/${a.id}/rename`, { name });
                              }}
                            >
                              Rename
                            </button>
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-zinc-400">
                        No authorized agents.
                      </p>
                    )}
                  </div>
                  <div>
                    <h3 className="mb-3 font-semibold">Permissions</h3>
                    <p className="mb-3 text-xs text-amber-600">
                      Changes affect every agent in this identity.
                    </p>
                    <Pills values={identity.grants} />
                  </div>
                </div>
              )}
            </section>
          );
        })
      )}
      <section className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="eyebrow">Git transport</p>
            <h2 className="mt-2 text-xl font-semibold">SSH transport</h2>
            <p className="mt-2 text-sm text-zinc-500">
              {data.ssh?.configured
                ? data.ssh.ready
                  ? `Ready on ${data.ssh.public_host}:${data.ssh.public_port}`
                  : "Configured but not ready"
                : "Disabled; Git access is unavailable"}
            </p>
            <p className="mt-1 text-xs text-zinc-400">
              Aggregate SSH operations: {data.git_transport_usage?.ssh_operations ?? 0}
            </p>
          </div>
          <div>
            <button
              className="button-secondary"
              onClick={() => act("/ui/ssh/host/prepare")}
            >
              Prepare host key
            </button>
          </div>
        </div>
        <div className="mt-4 grid gap-2 md:grid-cols-2">
          {data.ssh?.keys?.map((key) => (
            <div
              className="rounded-xl border border-zinc-200 p-3 text-xs dark:border-white/10"
              key={key.id}
            >
              <div className="flex items-center justify-between">
                <strong>Host key</strong>
                <span className={key.active ? "text-emerald-600" : "text-zinc-400"}>
                  {key.active ? "active" : key.retirement_time ? "retiring" : "prepared"}
                </span>
              </div>
              <code className="mt-2 block break-all text-[10px] text-zinc-500">
                {key.fingerprint}
              </code>
              {!key.active && !key.retirement_time && (
                <button
                  className="button-secondary mt-3"
                  onClick={() =>
                    act(`/ui/ssh/${key.purpose}/${key.id}/activate`)
                  }
                >
                  Activate
                </button>
              )}
              {!key.active && key.retirement_time && (
                <button
                  className="button-danger mt-3"
                  onClick={() =>
                    act(`/ui/ssh/${key.purpose}/${key.id}/retire`)
                  }
                >
                  Retire after overlap
                </button>
              )}
            </div>
          ))}
        </div>
        <p className="mt-3 text-xs text-zinc-500">
          Host-key activation requires SSH to be disabled and COG restarted.
        </p>
      </section>
      <footer className="flex items-center gap-2 text-xs text-zinc-500">
        <ShieldCheck size={14} /> Secrets and credential values are never
        displayed.
      </footer>
    </div>
  );
}
