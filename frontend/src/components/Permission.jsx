import React from "react";

export default function Permission({ permission }) {
  return (
    <label
      className={`grid grid-cols-[auto_1fr_auto] items-start gap-3 rounded-xl border p-4 transition ${permission.tone === "new" ? "border-blue-400/70 bg-blue-50/80 dark:bg-blue-500/10" : permission.tone === "other" ? "border-zinc-200 bg-white opacity-65 dark:border-white/10 dark:bg-black/20" : "border-zinc-200 bg-white dark:border-white/10 dark:bg-black/20"}`}
    >
      <input
        className="mt-1 size-4 accent-blue-500"
        type="checkbox"
        name={permission.field || undefined}
        value="on"
        defaultChecked={permission.checked}
        disabled={permission.disabled}
      />
      <span>
        <strong className="block text-sm">{permission.label}</strong>
        <span className="mt-1 block text-xs leading-5 text-zinc-500 dark:text-zinc-400">
          {permission.description}
        </span>
      </span>
      {permission.badge && (
        <span className="rounded-full bg-blue-100 px-2 py-1 text-[10px] font-bold uppercase tracking-wide text-blue-700 dark:bg-blue-500/15 dark:text-blue-200">
          {permission.badge}
        </span>
      )}
    </label>
  );
}
