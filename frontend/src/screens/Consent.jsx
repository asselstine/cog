import React, { useEffect, useState } from "react";
import { ChevronDown, ShieldCheck } from "lucide-react";
import { getJson } from "../api";
import Permission from "../components/Permission";

export default function Consent() {
  const [data, setData] = useState();
  const [error, setError] = useState();
  const [identity, setIdentity] = useState();
  useEffect(() => {
    getJson(`/api/oauth/consent${window.location.search}`)
      .then((payload) => {
        setData(payload);
        setIdentity(
          payload.fixedIdentity?.id || payload.identities[0]?.id || "",
        );
      })
      .catch((x) => setError(x.message));
  }, []);
  if (error)
    return (
      <div className="grid min-h-[70vh] place-items-center">
        <section className="card w-full max-w-xl p-8">
          <p className="eyebrow">Authorization paused</p>
          <h1 className="mt-3 text-3xl font-bold">Unable to continue</h1>
          <p className="mt-4 text-sm leading-6 text-zinc-500">{error}</p>
          <a className="button-secondary mt-6" href="/login">
            Sign in to COG
          </a>
        </section>
      </div>
    );
  if (!data)
    return (
      <div className="grid min-h-[70vh] place-items-center text-sm text-zinc-500">
        Loading authorization…
      </div>
    );
  const creating = !data.fixedIdentity && identity === "";
  return (
    <div className="grid min-h-[70vh] place-items-center py-8">
      <section className="card w-full max-w-2xl p-6 sm:p-9">
        <p className="eyebrow">Agent authorization</p>
        <h1 className="mt-3 text-3xl font-bold">Approve access</h1>
        <p className="mt-3 text-sm leading-6 text-zinc-500">
          Review access for this agent. Any grant change affects every agent
          connected to the selected identity.
        </p>
        <div className="my-6 flex items-center gap-3 rounded-xl border border-zinc-200 bg-zinc-50 p-4 dark:border-white/10 dark:bg-black/20">
          <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-blue-100 font-bold text-blue-600 dark:bg-blue-500/15 dark:text-blue-300">
            A
          </div>
          <div className="min-w-0">
            <div className="font-semibold">{data.client.name}</div>
            <div className="truncate text-xs text-zinc-500">
              <code>{data.client.id}</code> · Returns securely to{" "}
              {data.client.redirectHost}
            </div>
          </div>
        </div>
        <form method="post" action="/api/oauth/consent">
          <input type="hidden" name="consent" value={data.consent} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          {data.fixedIdentity ? (
            <>
              <input
                type="hidden"
                name="identity_id"
                value={data.fixedIdentity.id}
              />
              <div className="mb-6 rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm dark:border-white/10 dark:bg-black/20">
                <strong>Identity: {data.fixedIdentity.name}</strong>
                <div className="mt-1 text-zinc-500">
                  This existing agent cannot switch identities.
                </div>
              </div>
            </>
          ) : (
            <fieldset className="mb-7">
              <legend className="eyebrow mb-2">Identity</legend>
              <p className="mb-3 text-xs leading-5 text-zinc-500">
                Connections and permissions are shared by every agent in this
                identity.
              </p>
              <div className="relative">
                <select
                  className="input cursor-pointer appearance-none pr-10 font-semibold"
                  name="identity_id"
                  value={identity}
                  onChange={(event) => setIdentity(event.target.value)}
                >
                  {data.identities.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                  <option value="">New identity</option>
                </select>
                <ChevronDown
                  className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400"
                  size={18}
                />
              </div>
              {creating && (
                <label className="mt-4 block text-sm font-medium">
                  New identity name
                  <input
                    className="input mt-2"
                    name="new_identity_name"
                    maxLength="128"
                    required
                    autoFocus
                  />
                </label>
              )}
            </fieldset>
          )}
          <fieldset>
            <legend className="eyebrow mb-3">Permissions</legend>
            <div className="space-y-6">
              {data.permissionGroups.map((group) => (
                <section key={group.title}>
                  <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
                    {group.title}
                  </h2>
                  <div className="space-y-2">
                    {group.permissions.map((permission) => (
                      <Permission
                        key={
                          permission.field ||
                          permission.scope ||
                          permission.label
                        }
                        permission={permission}
                      />
                    ))}
                  </div>
                </section>
              ))}
            </div>
          </fieldset>
          <p className="mt-6 flex gap-2 text-xs leading-5 text-zinc-500">
            <ShieldCheck className="mt-0.5 shrink-0" size={15} /> You can revoke
            this agent from the COG dashboard at any time.
          </p>
          <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row">
            <button className="button-secondary" name="decision" value="deny">
              Cancel
            </button>
            <button className="button sm:ml-auto" name="decision" value="allow">
              Allow selected access
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
