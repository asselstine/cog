import React, { useState } from "react";
import { Cable, LogOut, Moon, Sun } from "lucide-react";

export default function Shell({ children, signedIn, signOut }) {
  const [dark, setDark] = useState(() =>
    document.documentElement.classList.contains("dark"),
  );
  return (
    <main className="mx-auto min-h-screen max-w-6xl px-5 py-8">
      <header className="mb-8 flex items-center gap-3">
        <div className="grid size-10 place-items-center rounded-xl bg-blue-500 text-white">
          <Cable size={21} />
        </div>
        <div>
          <b>COG</b>
          <div className="text-xs text-zinc-500">
            Clanker Operations Gateway
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {signedIn && (
            <button className="button-secondary h-9" onClick={signOut}>
              <LogOut size={16} /> Sign out
            </button>
          )}
          <button
            className="icon-button"
            onClick={() => {
              document.documentElement.classList.toggle("dark", !dark);
              setDark(!dark);
            }}
          >
            {dark ? <Sun size={17} /> : <Moon size={17} />}
          </button>
        </div>
      </header>
      {children}
    </main>
  );
}
