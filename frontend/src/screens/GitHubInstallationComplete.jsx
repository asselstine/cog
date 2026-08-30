import React from "react";
import { Check } from "lucide-react";

export default function GitHubInstallationComplete() {
  const integration = new URLSearchParams(window.location.search).get(
    "integration_id",
  );
  return (
    <div className="grid min-h-[70vh] place-items-center">
      <section className="card w-full max-w-xl p-8 text-center sm:p-10">
        <div className="mx-auto grid size-14 place-items-center rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300">
          <Check size={28} strokeWidth={2.5} />
        </div>
        <p className="eyebrow mt-6">GitHub connected</p>
        <h1 className="mt-3 text-3xl font-bold">GitHub App installed</h1>
        <p className="mt-4 text-sm leading-6 text-zinc-500">
          The GitHub integration is ready. You can close this window and retry
          repository access.
        </p>
        {integration && (
          <div className="mt-6 rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs text-zinc-500 dark:border-white/10 dark:bg-black/20">
            Integration <code>{integration}</code>
          </div>
        )}
        <button
          className="button-secondary mt-6"
          onClick={() => window.close()}
        >
          Close window
        </button>
      </section>
    </div>
  );
}
