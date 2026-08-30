import React, { useEffect, useState } from "react";
import { getJson, submit } from "./api";
import Shell from "./components/Shell";
import Consent from "./screens/Consent";
import Dashboard from "./screens/Dashboard";
import GitHubInstallationComplete from "./screens/GitHubInstallationComplete";
import Login from "./screens/Login";

export default function App() {
  const consent = window.location.pathname === "/oauth/authorize";
  const githubComplete =
    window.location.pathname === "/github/app/installation/complete";
  const standalone = consent || githubComplete;
  const [data, setData] = useState();
  const [error, setError] = useState("");
  async function load() {
    try {
      setData(await getJson("/api/ui"));
    } catch (x) {
      setError(x.message);
    }
  }
  useEffect(() => {
    if (!standalone) load();
  }, [standalone]);
  return (
    <Shell
      signedIn={!standalone && data?.mode === "admin"}
      signOut={async () => {
        await submit("/logout", { csrf_token: data.csrf_token });
        load();
      }}
    >
      {consent ? (
        <Consent />
      ) : githubComplete ? (
        <GitHubInstallationComplete />
      ) : error ? (
        <div>{error}</div>
      ) : !data ? (
        <div>Loading…</div>
      ) : data.mode === "admin" ? (
        <Dashboard data={data} reload={load} />
      ) : (
        <Login reload={load} />
      )}
    </Shell>
  );
}
