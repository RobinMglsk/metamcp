"use client";

import { useEffect, useState } from "react";

import { authClient } from "@/lib/auth-client";

export interface CurrentUser {
  id?: string;
  name?: string | null;
  email?: string | null;
  role?: string;
}

// Concurrent callers (sidebar, admin-only pages mounting together) share one
// session request; it is dropped once settled so a later sign-in as another
// user is picked up when the layout mounts again.
let sessionRequest: Promise<CurrentUser | null> | null = null;

function loadCurrentUser(): Promise<CurrentUser | null> {
  sessionRequest ??= authClient
    .getSession()
    .then((session) => (session?.data?.user as CurrentUser | undefined) ?? null)
    .catch(() => null)
    .finally(() => {
      sessionRequest = null;
    });
  return sessionRequest;
}

export function useCurrentUser() {
  const [state, setState] = useState<{
    user: CurrentUser | null;
    loading: boolean;
  }>({ user: null, loading: true });

  useEffect(() => {
    let active = true;
    loadCurrentUser().then((user) => {
      if (active) setState({ user, loading: false });
    });
    return () => {
      active = false;
    };
  }, []);

  return { ...state, isAdmin: state.user?.role === "admin" };
}
