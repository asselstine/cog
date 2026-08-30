import React, { useState } from "react";
import { submit } from "../api";

export default function Login({ reload }) {
  const [error, setError] = useState("");
  return (
    <div className="grid min-h-[70vh] place-items-center">
      <section className="card w-full max-w-md p-8">
        <p className="eyebrow">Welcome back</p>
        <h1 className="mt-3 text-3xl font-bold">Sign in to COG</h1>
        <p className="mt-3 text-sm text-zinc-500">
          Manage identities, connections, agents, and permissions.
        </p>
        <form
          className="mt-7 space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await submit(
                "/login",
                Object.fromEntries(new FormData(e.currentTarget)),
              );
              reload();
            } catch (x) {
              setError(x.message);
            }
          }}
        >
          <label className="block text-sm">
            Email
            <input className="input mt-2" name="email" type="email" required />
          </label>
          <label className="block text-sm">
            Password
            <input
              className="input mt-2"
              name="password"
              type="password"
              required
            />
          </label>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button className="button w-full">Sign in</button>
        </form>
      </section>
    </div>
  );
}
