import { render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { onUnauthorized } from "../api/http";
import { server } from "../test/server";
import {
  applyTheme,
  cachedTheme,
  cacheTheme,
  decode,
  encode,
  paletteFor,
  THEME_STORAGE_KEY,
} from "./applyTheme";
import { SKINS } from "./palettes";
import { AuthContextForTests, AuthProvider } from "../auth/AuthProvider";
import { ToastProvider } from "../components/toast/ToastProvider";
import { ThemePicker } from "./ThemePicker";
import { ThemeProvider } from "./ThemeProvider";

/**
 * The provider under test, with the auth context it now reads.
 *
 * `ThemeProvider` sits inside `AuthProvider` because the theme is a property of
 * the session: the reconcile has to re-ask when the identity changes, and
 * sign-in is SPA-local.
 */
/**
 * A session this test controls, in place of `AuthProvider`.
 *
 * `ThemeProvider` reads only `session?.username`, and driving that directly is
 * what lets the sign-in case change the identity WITHOUT remounting — which is
 * the whole point, since a remount re-runs a mount-scoped effect and would let
 * the defect pass.
 */
function FakeAuth({
  username,
  children,
}: {
  username: string | null;
  children: React.ReactNode;
}) {
  const value = {
    session: username === null ? null : { username, role: "examiner" },
  };
  return (
    <AuthContextForTests.Provider value={value as never}>
      {children}
    </AuthContextForTests.Provider>
  );
}

function Themed({ children }: { children: React.ReactNode }) {
  return (
    <ToastProvider>
      <AuthProvider>
        <ThemeProvider>{children}</ThemeProvider>
      </AuthProvider>
    </ToastProvider>
  );
}

function root(): HTMLElement {
  return document.documentElement;
}

beforeEach(() => {
  window.localStorage.clear();
  applyTheme(null, root());
});

/** A stored session, which is what makes the provider ask the server at all. */
function signedIn() {
  window.localStorage.setItem(
    "seance_session",
    JSON.stringify({ username: "ivy", role: "examiner" }),
  );
}

afterEach(() => {
  applyTheme(null, root());
});

describe("encoding a theme", () => {
  it("round-trips through the form the server stores", () => {
    expect(encode({ skin: "nature", mode: "light" })).toBe("nature:light");
    expect(decode("nature:light")).toEqual({ skin: "nature", mode: "light" });
  });

  it("refuses anything that is not a theme this build has", () => {
    // The server validates the SHAPE and deliberately not the catalogue, so a
    // client one version behind will meet a skin it does not know. That is an
    // ordinary state, not an error: fall back to the default rather than fail
    // to render.
    expect(decode("nature:sideways")).toBeNull();
    expect(decode("a-skin-from-the-future:dark")).toBeNull();
    expect(decode("nature")).toBeNull();
    expect(decode("")).toBeNull();
    expect(decode(null)).toBeNull();
    expect(decode(undefined)).toBeNull();
  });
});

describe("applying a theme", () => {
  it("writes every token of the palette, and the colour scheme", () => {
    applyTheme({ skin: "cyber", mode: "light" }, root());
    const palette = paletteFor({ skin: "cyber", mode: "light" });

    for (const [name, value] of Object.entries(palette)) {
      if (name === "color-scheme") continue;
      expect(root().style.getPropertyValue(`--${name}`), name).toBe(value);
    }
    // Not a custom property: it is what makes the browser draw form controls,
    // scrollbars and the canvas behind the app to match.
    expect(root().style.getPropertyValue("color-scheme")).toBe("light");
    expect(root().getAttribute("data-skin")).toBe("cyber");
    expect(root().getAttribute("data-mode")).toBe("light");
  });

  it("leaves nothing of one skin behind when another is applied", () => {
    applyTheme({ skin: "nature", mode: "dark" }, root());
    applyTheme({ skin: "win11", mode: "light" }, root());

    const win11 = paletteFor({ skin: "win11", mode: "light" });
    for (const [name, value] of Object.entries(win11)) {
      if (name === "color-scheme") continue;
      expect(root().style.getPropertyValue(`--${name}`), name).toBe(value);
    }
    expect(root().style.getPropertyValue("--bg-0")).not.toBe(
      SKINS.nature.dark["bg-0"],
    );
  });

  it("clears back to the stylesheet rather than writing the default over it", () => {
    // Removing the properties makes the tokens fall back to `index.css`, which
    // is one source of truth. Writing the default palette's values would be a
    // second copy of it, free to drift.
    applyTheme({ skin: "relax", mode: "dark" }, root());
    expect(root().style.getPropertyValue("--bg-0")).not.toBe("");

    applyTheme(null, root());
    expect(root().style.getPropertyValue("--bg-0")).toBe("");
    expect(root().style.getPropertyValue("color-scheme")).toBe("");
    expect(root().hasAttribute("data-skin")).toBe(false);
  });
});

describe("the browser cache", () => {
  it("remembers and forgets", () => {
    cacheTheme({ skin: "opus", mode: "light" });
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("opus:light");
    expect(cachedTheme()).toEqual({ skin: "opus", mode: "light" });

    cacheTheme(null);
    expect(cachedTheme()).toBeNull();
  });

  it("survives a browser that refuses to store anything", () => {
    // Not hypothetical: `localStorage` throws outright in a browser configured
    // to block site data. A theme is not worth failing to start over.
    const original = Object.getOwnPropertyDescriptor(window, "localStorage");
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new Error("site data is blocked");
      },
    });
    try {
      expect(() => cacheTheme({ skin: "cyber", mode: "dark" })).not.toThrow();
      expect(cachedTheme()).toBeNull();
    } finally {
      if (original) Object.defineProperty(window, "localStorage", original);
    }
  });
});

describe("remembering a theme across sessions", () => {
  function meReturns(theme: string | null) {
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({ authenticated: true, username: "ivy", theme }),
      ),
    );
  }

  it("paints the cached theme before the server has answered", () => {
    // The point of the cache. Without it a cold load paints the default palette
    // and swaps it when /auth/me lands, which is the flash an examiner who
    // chose a light skin notices most.
    signedIn();
    window.localStorage.setItem(THEME_STORAGE_KEY, "nature:light");
    meReturns("nature:light");

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );
    expect(root().getAttribute("data-skin")).toBe("nature");
  });

  it("takes the server’s answer over the browser’s when they disagree", async () => {
    // The server is the record; the browser is a cache. This is what makes the
    // choice follow an examiner to the second workstation in the lab.
    signedIn();
    window.localStorage.setItem(THEME_STORAGE_KEY, "nature:light");
    meReturns("cyber:dark");

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );

    await waitFor(() => expect(root().getAttribute("data-skin")).toBe("cyber"));
    expect(root().getAttribute("data-mode")).toBe("dark");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("cyber:dark");
  });

  it("honours the server saying the user has no stored choice", async () => {
    // A cleared setting on another machine has to reach this one, or "stored
    // against your account" is only true in one direction.
    signedIn();
    window.localStorage.setItem(THEME_STORAGE_KEY, "relax:dark");
    meReturns(null);

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );

    await waitFor(() =>
      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBeNull(),
    );
    expect(root().hasAttribute("data-skin")).toBe(false);
  });

  it("fetches the account’s theme when someone signs in, not only at mount", async () => {
    // The defect this exists for, and it defeated the whole feature. The
    // reconcile ran once on mount and never again, gated on a mount-time read
    // of the stored session — and sign-in is SPA-local, with no reload. So any
    // page load that STARTED signed out never fetched the account's theme:
    // signing in on the second workstation gave the default palette until a
    // manual reload.
    //
    // The session is driven directly rather than through a re-render with a new
    // key, because a remount re-runs a mount-scoped effect too — a test that
    // remounted would pass against the defect and prove nothing.
    let asked = 0;
    server.use(
      http.get("/api/v1/auth/me", () => {
        asked += 1;
        return HttpResponse.json({
          authenticated: true,
          username: "ivy",
          theme: "cyber:dark",
        });
      }),
    );

    function Harness() {
      const [user, setUser] = useState<string | null>(null);
      return (
        <FakeAuth username={user}>
          <ThemeProvider>
            <button onClick={() => setUser("ivy")}>sign in</button>
          </ThemeProvider>
        </FakeAuth>
      );
    }

    render(<Harness />);
    // Signed out: nobody to have a preference, and no request for one.
    await screen.findByRole("button", { name: "sign in" });
    expect(asked).toBe(0);
    expect(root().hasAttribute("data-skin")).toBe(false);

    // The session appears without the tree remounting, exactly as an SPA login
    // leaves things.
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));
    await waitFor(() => expect(root().getAttribute("data-skin")).toBe("cyber"));
    expect(asked).toBe(1);
  });

  it("gives a second examiner on one workstation their own theme", async () => {
    // The shared-workstation half. Examiner A's choice is in this browser's
    // cache; B signs in and must not inherit it for the session.
    signedIn();
    window.localStorage.setItem(THEME_STORAGE_KEY, "nature:light");
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({
          authenticated: true,
          username: "jack",
          theme: "relax:dark",
        }),
      ),
    );

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );

    await waitFor(() => expect(root().getAttribute("data-skin")).toBe("relax"));
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("relax:dark");
  });

  it("keeps the cached theme when the server cannot be reached", async () => {
    signedIn();
    window.localStorage.setItem(THEME_STORAGE_KEY, "win11:dark");
    server.use(http.get("/api/v1/auth/me", () => HttpResponse.error()));

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );

    await screen.findByText("ready");
    expect(root().getAttribute("data-skin")).toBe("win11");
  });
});

describe("the picker", () => {
  beforeEach(() => {
    signedIn();
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({
          authenticated: true,
          username: "ivy",
          theme: null,
        }),
      ),
    );
  });

  it("applies a choice at once and sends it to be remembered", async () => {
    let sent: unknown = undefined;
    server.use(
      http.put("/api/v1/auth/theme", async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json({ theme: "nature:dark" });
      }),
    );

    render(
      <Themed>
        <ThemePicker />
      </Themed>,
    );

    await userEvent.click(screen.getByRole("button", { name: /Nature dark/i }));

    expect(root().getAttribute("data-skin")).toBe("nature");
    expect(root().getAttribute("data-mode")).toBe("dark");
    await waitFor(() => expect(sent).toEqual({ theme: "nature:dark" }));
  });

  it("marks the chosen theme in a way that is not colour", async () => {
    server.use(
      http.put("/api/v1/auth/theme", () => HttpResponse.json({ theme: null })),
    );
    render(
      <Themed>
        <ThemePicker />
      </Themed>,
    );

    const relax = screen.getByRole("button", { name: /Relax light/i });
    expect(relax).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(relax);
    expect(relax).toHaveAttribute("aria-pressed", "true");
  });

  it("says so when the choice was applied but not saved", async () => {
    // The setting claims the theme is remembered. If it was applied and not
    // stored, an examiner signing in tomorrow gets the old one back with no
    // way to know why — a product that quietly forgets rather than one that
    // failed.
    server.use(http.put("/api/v1/auth/theme", () => HttpResponse.error()));

    render(
      <Themed>
        <ThemePicker />
      </Themed>,
    );

    await userEvent.click(screen.getByRole("button", { name: /Cyber dark/i }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/could not be saved/i);
    expect(alert.textContent).toMatch(/failed request, not a rejected choice/i);
    // And it is applied anyway: losing the change as well would be worse.
    expect(root().getAttribute("data-skin")).toBe("cyber");
  });

  it("offers the default as a choice of its own", async () => {
    let sent: unknown = "unset";
    server.use(
      http.put("/api/v1/auth/theme", async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json({ theme: null });
      }),
    );

    render(
      <Themed>
        <ThemePicker />
      </Themed>,
    );

    await userEvent.click(screen.getByRole("button", { name: /^Default/ }));
    // `null`, not the default palette spelled out: "I never chose" and "I chose
    // the one that happens to be the default" are different, and only the first
    // should move if the default ever does.
    await waitFor(() => expect(sent).toEqual({ theme: null }));
  });

  it("never asks the server when nobody is signed in", async () => {
    // On the login screen there is nobody to have a preference, and asking adds
    // a 401 to every cold load for nothing.
    let asked = false;
    server.use(
      http.get("/api/v1/auth/me", () => {
        asked = true;
        return HttpResponse.json({ authenticated: false });
      }),
    );
    window.localStorage.removeItem("seance_session");
    window.localStorage.setItem(THEME_STORAGE_KEY, "opus:dark");

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );
    await screen.findByText("ready");
    expect(asked).toBe(false);
    // And the cached theme is still applied: not asking is not forgetting.
    expect(root().getAttribute("data-skin")).toBe("opus");
  });

  it("a 401 on the theme read cannot sign the examiner out", async () => {
    // `apiFetch` fires the global 401 listeners and `AuthProvider` logs out on
    // those. A display preference must never be able to end a session — not on
    // a stale cookie, not on a race — so this read is kept off that path.
    signedIn();
    let loggedOut = false;
    const stop = onUnauthorized(() => {
      loggedOut = true;
    });
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({ authenticated: false }, { status: 401 }),
      ),
    );

    render(
      <Themed>
        <div>ready</div>
      </Themed>,
    );
    await screen.findByText("ready");
    await new Promise((resolve) => setTimeout(resolve, 0));
    stop();
    expect(loggedOut).toBe(false);
  });
});
