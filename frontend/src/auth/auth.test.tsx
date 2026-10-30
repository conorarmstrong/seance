import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import {
  clearToken,
  getToken,
  notifyUnauthorized,
  setToken,
} from "../api/http";
import { server } from "../test/server";
import { AuthProvider, useAuth } from "./AuthProvider";
// AuthProvider surfaces a failed logout revocation through the toast API, so
// it now needs the provider it has in App.tsx.
import { ToastProvider } from "../components/toast/ToastProvider";

function Probe() {
  const { session, login, logout } = useAuth();
  if (!session) {
    return (
      <button onClick={() => login("admin", "seance").catch(() => {})}>
        do-login
      </button>
    );
  }
  return (
    <div>
      <span>signed in as {session.username}</span>
      <button onClick={logout}>do-logout</button>
    </div>
  );
}

function MustChangeProbe() {
  const { session, login, changePassword } = useAuth();
  if (!session) {
    return (
      <button onClick={() => login("admin", "seance").catch(() => {})}>
        do-login
      </button>
    );
  }
  if (session.mustChangePassword) {
    return (
      <div>
        <span>must-change</span>
        <button
          onClick={() => changePassword("a-strong-new-pw").catch(() => {})}
        >
          do-change
        </button>
      </div>
    );
  }
  return <span>full access as {session.username}</span>;
}

function mockAuthApi(valid = true) {
  server.use(
    http.get("/api/v1/auth/me", () =>
      HttpResponse.json(
        { authenticated: false },
        { headers: { "Set-Cookie": "seance_csrf=csrf-1; Path=/" } },
      ),
    ),
    http.post("/api/v1/auth/login", async ({ request }) => {
      const body = (await request.json()) as { username: string };
      if (!valid) {
        return HttpResponse.json(
          { error: { code: "INVALID_CREDENTIALS", message: "bad" } },
          { status: 401 },
        );
      }
      return HttpResponse.json({
        token: "jwt-token",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        username: body.username,
        role: "admin",
      });
    }),
    http.post("/api/v1/auth/logout", () =>
      HttpResponse.json({ message: "Logged out successfully" }),
    ),
  );
}

afterEach(() => {
  clearToken();
  localStorage.clear();
});

describe("auth", () => {
  it("logs in, stores the token, and exposes the session", async () => {
    mockAuthApi();
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("do-login"));
    expect(await screen.findByText("signed in as admin")).toBeInTheDocument();
    expect(getToken()).toBe("jwt-token");
  });

  it("does not persist the JWT to localStorage on login (BUG-200)", async () => {
    mockAuthApi();
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("do-login"));
    expect(await screen.findByText("signed in as admin")).toBeInTheDocument();
    // The token is usable in-memory for the active tab...
    expect(getToken()).toBe("jwt-token");
    // ...but is never written to localStorage: no legacy seance_token key, and
    // the persisted session record carries no JWT.
    expect(localStorage.getItem("seance_token")).toBeNull();
    const stored = JSON.parse(localStorage.getItem("seance_session") ?? "{}");
    expect(stored.username).toBe("admin");
    expect(stored.token).not.toBe("jwt-token");
  });

  it("scrubs a JWT left in a persisted session by an older build (BUG-200)", () => {
    localStorage.setItem(
      "seance_session",
      JSON.stringify({
        token: "legacy-jwt",
        username: "admin",
        role: "admin",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    );
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    expect(screen.getByText("signed in as admin")).toBeInTheDocument();
    // The stale JWT is scrubbed from the persisted record on load.
    const stored = JSON.parse(localStorage.getItem("seance_session") ?? "{}");
    expect(stored.token).not.toBe("legacy-jwt");
    expect(getToken()).toBeNull();
  });

  it("rejects bad credentials and stays signed out", async () => {
    mockAuthApi(false);
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("do-login"));
    await waitFor(() => expect(getToken()).toBeNull());
    expect(screen.getByText("do-login")).toBeInTheDocument();
  });

  it("restores a stored unexpired session on mount", () => {
    localStorage.setItem(
      "seance_session",
      JSON.stringify({
        token: "stored-token",
        username: "admin",
        role: "admin",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    );
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    expect(screen.getByText("signed in as admin")).toBeInTheDocument();
  });

  it("discards an expired stored session", () => {
    localStorage.setItem(
      "seance_session",
      JSON.stringify({
        token: "stale",
        username: "admin",
        role: "admin",
        expires_at: Math.floor(Date.now() / 1000) - 10,
      }),
    );
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    expect(screen.getByText("do-login")).toBeInTheDocument();
  });

  it("clears the JWT too when discarding an expired stored session (BUG-071)", () => {
    setToken("stale-jwt");
    localStorage.setItem(
      "seance_session",
      JSON.stringify({
        token: "stale-jwt",
        username: "admin",
        role: "admin",
        expires_at: Math.floor(Date.now() / 1000) - 10,
      }),
    );
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    expect(screen.getByText("do-login")).toBeInTheDocument();
    // The token must not survive an expired session (getToken() would otherwise
    // keep handing out the stale JWT while the UI shows logged-out).
    expect(getToken()).toBeNull();
    expect(localStorage.getItem("seance_token")).toBeNull();
  });

  it("clears the JWT on a corrupt stored session (BUG-071)", () => {
    setToken("stale-jwt");
    localStorage.setItem("seance_session", "{ not valid json");
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    expect(screen.getByText("do-login")).toBeInTheDocument();
    expect(getToken()).toBeNull();
    expect(localStorage.getItem("seance_token")).toBeNull();
  });

  it("forces a password change on a must-change session, then clears it", async () => {
    let rotated = false;
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({ authenticated: false }),
      ),
      http.post("/api/v1/auth/login", async ({ request }) => {
        const body = (await request.json()) as { username: string };
        return HttpResponse.json({
          token: "jwt-token",
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          username: body.username,
          role: "admin",
          must_change_password: !rotated,
          user_id: "admin-id",
        });
      }),
      http.post("/api/v1/users/admin-id/password", () => {
        rotated = true;
        return HttpResponse.json({ message: "ok" });
      }),
    );
    render(
      <ToastProvider>
        <AuthProvider>
          <MustChangeProbe />
        </AuthProvider>
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("do-login"));
    // The must-change session is confined to the change-password screen.
    expect(await screen.findByText("must-change")).toBeInTheDocument();
    // Rotating the password re-logs in and yields full access.
    await userEvent.click(screen.getByText("do-change"));
    expect(await screen.findByText("full access as admin")).toBeInTheDocument();
  });

  it("logs out and clears the token", async () => {
    mockAuthApi();
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("do-login"));
    await screen.findByText("signed in as admin");
    await userEvent.click(screen.getByText("do-logout"));
    await waitFor(() => expect(getToken()).toBeNull());
    expect(screen.getByText("do-login")).toBeInTheDocument();
  });

  it("clears the server auth cookie on a 401, not just local state (BUG-235)", async () => {
    let logoutCalls = 0;
    mockAuthApi();
    server.use(
      http.post("/api/v1/auth/logout", () => {
        logoutCalls += 1;
        return HttpResponse.json({ message: "Logged out successfully" });
      }),
    );
    render(
      <ToastProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("do-login"));
    await screen.findByText("signed in as admin");
    expect(logoutCalls).toBe(0);

    // A 401 from any API call tears the session down. Local state alone is not
    // enough: the HttpOnly seance_auth cookie must be cleared server-side too.
    await act(async () => {
      notifyUnauthorized();
    });

    await waitFor(() => expect(getToken()).toBeNull());
    expect(screen.getByText("do-login")).toBeInTheDocument();
    await waitFor(() => expect(logoutCalls).toBe(1));
  });
});
