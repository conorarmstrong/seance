import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { apiFetch, apiUrl, getToken } from "../api/http";
import { useAuth } from "../auth/AuthProvider";
import {
  applyTheme,
  cacheTheme,
  cachedTheme,
  decode,
  encode,
  type Theme,
} from "./applyTheme";

interface ThemeContextValue {
  /** The applied theme, or `null` for the palette `index.css` declares. */
  theme: Theme | null;
  /**
   * Choose a theme, or `null` to go back to following the build's default.
   *
   * Applied to the document immediately, cached in the browser immediately, and
   * written to the server in the background. The order is deliberate: the
   * examiner's click must not wait on a round trip, and a server that cannot be
   * reached must not cost them the change for this session.
   */
  setTheme: (theme: Theme | null) => void;
  /**
   * Whether the last attempt to *remember* a theme failed.
   *
   * Surfaced rather than swallowed. The setting says the choice is remembered;
   * if it was applied but not stored, an examiner who signs in tomorrow gets
   * the old one back and has no way to know why. Saying so is the difference
   * between a preference that failed and a product that forgets.
   */
  saveFailed: boolean;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

/**
 * Holds the chosen skin and keeps three copies of it in step: the document, the
 * browser cache, and the user's row on the server.
 *
 * # Which of the three is the record
 *
 * The server. The browser copy exists so the first paint of a cold load is the
 * examiner's own palette rather than the default one swapped a moment later,
 * and it is corrected the moment `/auth/me` answers. That answer travels with
 * the identity — the same request that says who you are says how you want to
 * see it — so reconciling costs no extra round trip.
 *
 * Storing it per user rather than per browser is the point of "remembered": an
 * examiner who has set up a workstation they can read should not have to do it
 * again on the second machine in the lab, or after clearing site data.
 *
 * # Why this sits INSIDE `AuthProvider`
 *
 * It sat outside, so that it could paint before anything else rendered. That was
 * unnecessary — `main.tsx` applies the cached theme synchronously before React
 * mounts, which is what actually prevents the flash — and it cost the feature
 * its whole promise. Outside the auth context there is no session to react to,
 * so the reconcile ran once at mount and never again; sign-in is SPA-local with
 * no reload, so **any page load that started signed out never fetched the
 * account's theme at all**. Signing in on the second workstation gave the
 * default palette until a manual reload, and on a shared workstation the second
 * examiner kept the first one's cached skin for the whole session.
 *
 * Keyed on the username rather than on "is there a session", so a different
 * examiner signing in on the same machine is a different question and is asked
 * again.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const username = session?.username ?? null;
  const [theme, setThemeState] = useState<Theme | null>(() => cachedTheme());
  const [saveFailed, setSaveFailed] = useState(false);
  /**
   * Whether the examiner has chosen during this mount.
   *
   * A ref rather than state because the in-flight reconcile below has to read
   * it at the moment its response lands, not at the moment its effect closed
   * over it — and because changing it must not itself cause a render.
   */
  const chosenRef = useRef(false);
  /**
   * Which save is the current one. Bumped per choice, so a response landing out
   * of order can be told from the one that speaks for what is on screen.
   */
  const saveGeneration = useRef(0);

  // Paint on mount and on every change. `applyTheme` writes custom properties
  // onto the root element, so this is the only place the DOM is touched.
  useEffect(() => {
    applyTheme(theme, document.documentElement);
  }, [theme]);

  // Reconcile with the server once, and only where there is a session to
  // reconcile against.
  //
  // Two things here are deliberate and both are about not letting a colour
  // scheme cost an examiner anything.
  //
  // **It is a raw `fetch`, not `apiFetch`.** `apiFetch` fires the global 401
  // listeners, and `AuthProvider` logs out on those. A *display preference*
  // must never be able to sign someone out — not on a stale cookie, not on a
  // race, not ever — so this read is kept off that path entirely.
  //
  // **It is skipped with no session.** On the login screen there is nobody to
  // have a preference, and asking would add a 401 to every cold load for
  // nothing.
  //
  // A failure is silent HERE and only here: nobody asked for this read. A
  // failure to *save*, which they did ask for, is reported.
  useEffect(() => {
    if (!username) return;

    // A fresh identity gets a fresh answer: a choice the PREVIOUS examiner made
    // on this machine must not suppress the reconcile for this one, which is
    // what a mount-scoped flag would do on a shared workstation.
    chosenRef.current = false;

    let cancelled = false;
    // Raw `fetch` is off the 401-logout path, but it is also off the path that
    // adds the Bearer header. Where the session is a cookie that is enough;
    // where it is a token held in memory, a request without the header is an
    // unauthenticated one and the reconcile silently learns nothing. Same
    // header `apiFetch` would send, without the listener it would fire.
    const token = getToken();
    fetch(apiUrl("/auth/me"), {
      credentials: "same-origin",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((res) => (res.ok ? res.json() : null))
      .then(
        (body: { authenticated?: boolean; theme?: string | null } | null) => {
          if (cancelled || !body?.authenticated) return;
          // A choice made WHILE this was in flight wins over it. The request was
          // sent to learn what the examiner had already chosen; if they have
          // since chosen again, this answer is stale by definition, and applying
          // it reverts both the document and the cache under them — the setting
          // appearing not to work until a reload.
          if (chosenRef.current) return;
          const stored = decode(body.theme);
          // Otherwise the server's answer wins, including when it is "no choice
          // stored": that is what a user sees after clearing the setting on
          // another machine, and honouring it is the whole reason the record is
          // central.
          setThemeState(stored);
          cacheTheme(stored);
        },
      )
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [username]);

  const setTheme = useCallback((next: Theme | null) => {
    chosenRef.current = true;
    setThemeState(next);
    cacheTheme(next);
    setSaveFailed(false);
    // Two quick picks are two unsequenced writes, and the server keeps whichever
    // lands last — which need not be the one on screen. A generation stamp makes
    // the LATEST choice the only one that can report anything, so a slow first
    // request cannot flip `saveFailed` on for a theme that did save.
    saveGeneration.current += 1;
    const generation = saveGeneration.current;
    apiFetch("/auth/theme", {
      method: "PUT",
      body: { theme: next === null ? null : encode(next) },
    }).catch(() => {
      if (generation === saveGeneration.current) setSaveFailed(true);
    });
  }, []);

  const value = useMemo(
    () => ({ theme, setTheme, saveFailed }),
    [theme, setTheme, saveFailed],
  );
  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext);
  if (value === null) {
    throw new Error("useTheme must be used inside a ThemeProvider");
  }
  return value;
}
