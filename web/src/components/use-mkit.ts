"use client";

import { useEffect, useState } from "react";
import { mkit, type MkitApi } from "../lib/mkit";

type State =
  | { status: "loading" }
  | { status: "ready"; api: MkitApi }
  | { status: "error"; error: Error };

export function useMkit(): State {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    mkit()
      .then((api) => {
        if (!cancelled) setState({ status: "ready", api });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            status: "error",
            error: error instanceof Error ? error : new Error(String(error)),
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
