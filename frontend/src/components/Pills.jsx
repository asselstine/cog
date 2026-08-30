import React from "react";

const Pills = ({ values = [] }) => (
  <div className="flex flex-wrap gap-1.5">
    {values.length ? (
      values.map((v) => (
        <span
          key={v}
          className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs dark:bg-white/5"
        >
          {v}
        </span>
      ))
    ) : (
      <span className="text-xs text-zinc-400">none</span>
    )}
  </div>
);

export default Pills;
