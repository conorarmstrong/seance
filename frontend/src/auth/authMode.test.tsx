import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { clearToken } from "../api/http";
import { RequireAuth } from "../app/RequireAuth";
import { server } from "../test/server";
import { AuthProvider } from "./AuthProvider";
import { detectAuthMode } from "./authMode";
import { LoginPage } from "./LoginPage";
// AuthProvider surfaces a failed logout revocation through the toast API, so
// it now needs the provider it has in App.tsx.
import { ToastProvider } from "../components/toast/ToastProvider";

/** `/auth/me` as the server answers it with no credentials presented. */
function meUnauthenticated(extra: Record<string, unknown> = {}) {
  return http.get("/api/v1/auth/me", () =>
    HttpResponse.json({ authenticated: false, ...extra }),
  );
}

/** `/auth/me` as the server answers it when a cookie authenticates the tab. */
function meAuthenticated() {
  return http.get("/api/v1/auth/me", () =>
    HttpResponse.json({
      authenticated: true,
      username: "admin",
      role: "admin",
      must_change_password: false,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    }),
  );
}

/** The protected route the probe uses, answering as an auth-enabled server does. */
function casesRequireAuth() {
  return http.get("/api/v1/cases", () =>
    HttpResponse.json(
      { error: { code: "UNAUTHORIZED", message: "Authentication required" } },
      { status: 401 },
    ),
  );
}

/** The same route on a server started with SEANCE_AUTH_ENABLED=false. */
function casesOpen() {
  return http.get("/api/v1/cases", () => HttpResponse.json([]));
}

afterEach(() => {
  clearToken();
  localStorage.clear();
});

describe("detectAuthMode (LIVE-004)", () => {
  it("reports disabled when a protected route answers 200 with no credentials", async () => {
    server.use(meUnauthenticated(), casesOpen());
    await expect(detectAuthMode()).resolves.toBe("disabled");
  });

  it("reports enabled when the protected route demands credentials", async () => {
    server.use(meUnauthenticated(), casesRequireAuth());
    await expect(detectAuthMode()).resolves.toBe("enabled");
  });

  it('never reads a 200 that a session cookie earned as "auth is off"', async () => {
    // The dangerous case: the tab holds an HttpOnly `seance_auth` cookie that
    // JS cannot see, so the protected route answers 200 on a server that fully
    // enforces auth. Concluding "disabled" here would present a real,
    // attributable session as an anonymous one.
    server.use(meAuthenticated(), casesOpen());
    await expect(detectAuthMode()).resolves.toBe("enabled");
  });

  it("prefers an explicit auth_enabled from the server over the probe", async () => {
    // The probe is a fallback. Once the server states its mode, that answer is
    // taken even where the probe would disagree.
    server.use(meUnauthenticated({ auth_enabled: true }), casesOpen());
    await expect(detectAuthMode()).resolves.toBe("enabled");

    server.use(meUnauthenticated({ auth_enabled: false }), casesRequireAuth());
    await expect(detectAuthMode()).resolves.toBe("disabled");
  });

  it("fails closed when the server cannot be reached or answers oddly", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.error()),
      casesOpen(),
    );
    await expect(detectAuthMode()).resolves.toBe("enabled");

    server.use(
      http.get(
        "/api/v1/auth/me",
        () => new HttpResponse("nope", { status: 500 }),
      ),
      casesOpen(),
    );
    await expect(detectAuthMode()).resolves.toBe("enabled");

    // 200 with a body that is not the shape we know: unreadable, so unusable.
    server.use(
      http.get(
        "/api/v1/auth/me",
        () => new HttpResponse("<html/>", { status: 200 }),
      ),
      casesOpen(),
    );
    await expect(detectAuthMode()).resolves.toBe("enabled");

    // The probe itself failing is not permission to skip the login.
    server.use(
      meUnauthenticated(),
      http.get("/api/v1/cases", () => HttpResponse.error()),
    );
    await expect(detectAuthMode()).resolves.toBe("enabled");
  });
});

function renderGuarded() {
  render(
    <ToastProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/"]}>
          <Routes>
            <Route element={<RequireAuth />}>
              <Route path="/" element={<div>protected view</div>} />
            </Route>
            <Route path="/login" element={<div>login screen</div>} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </ToastProvider>,
  );
}

describe("RequireAuth against a server with auth disabled (LIVE-004)", () => {
  it("serves the app instead of redirecting to a login that cannot complete", async () => {
    server.use(meUnauthenticated(), casesOpen());
    renderGuarded();
    expect(await screen.findByText("protected view")).toBeInTheDocument();
    expect(screen.queryByText("login screen")).not.toBeInTheDocument();
  });

  it("still redirects to the login on a server that enforces auth", async () => {
    server.use(meUnauthenticated(), casesRequireAuth());
    renderGuarded();
    expect(await screen.findByText("login screen")).toBeInTheDocument();
    expect(screen.queryByText("protected view")).not.toBeInTheDocument();
  });

  it("sends the examiner off the login form when there is no sign-in to complete", async () => {
    // A bookmark or a stale tab lands on /login directly. On a server started
    // with SEANCE_AUTH_ENABLED=false there are no credentials to check, so the
    // form can never succeed — leaving it up presents a locked door where
    // there is none.
    server.use(meUnauthenticated(), casesOpen());
    render(
      <ToastProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={["/login"]}>
            <Routes>
              <Route path="/" element={<div>protected view</div>} />
              <Route path="/login" element={<LoginPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ToastProvider>,
    );

    expect(await screen.findByText("protected view")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Sign in/ }),
    ).not.toBeInTheDocument();
  });

  it("keeps the login form up on a server that does enforce a sign-in", async () => {
    server.use(meUnauthenticated(), casesRequireAuth());
    render(
      <ToastProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={["/login"]}>
            <Routes>
              <Route path="/" element={<div>protected view</div>} />
              <Route path="/login" element={<LoginPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ToastProvider>,
    );

    expect(
      await screen.findByRole("button", { name: /Sign in/ }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByText("protected view")).not.toBeInTheDocument(),
    );
  });

  it("shows neither the app nor the login while the mode is undetermined", async () => {
    let answer: (() => void) | null = null;
    const held = new Promise<void>((resolve) => {
      answer = resolve;
    });
    server.use(
      http.get("/api/v1/auth/me", async () => {
        await held;
        return HttpResponse.json({ authenticated: false });
      }),
      casesRequireAuth(),
    );
    renderGuarded();

    expect(
      await screen.findByText(
        "Checking whether this server requires a sign-in…",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText("protected view")).not.toBeInTheDocument();
    expect(screen.queryByText("login screen")).not.toBeInTheDocument();

    answer!();
    await waitFor(() =>
      expect(screen.getByText("login screen")).toBeInTheDocument(),
    );
  });
});
