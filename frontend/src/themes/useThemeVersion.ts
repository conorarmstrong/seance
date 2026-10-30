import { useEffect, useState } from "react";

/**
 * A value that changes whenever the applied theme does.
 *
 * For anything that paints from the tokens **once** and cannot re-resolve them
 * afterwards — a canvas, most obviously, which holds pixels rather than a live
 * style. Such a component needs a redraw trigger, and this is it.
 *
 * # Why this and not `useTheme()`
 *
 * `useTheme` requires the provider, and a component that throws without one
 * turns a display preference into a hard dependency for every part of the tree
 * that happens to touch a colour — a wiring mistake that crashes a page rather
 * than showing it in the wrong palette. It also made three unrelated test files
 * wrap a provider around components whose subject is not the theme.
 *
 * The honest dependency is the **document**: `applyTheme` writes the tokens onto
 * the root element and stamps `data-skin` / `data-mode` beside them, so watching
 * those attributes catches every route by which a theme can change, including
 * ones that do not go through the provider at all. A component that renders
 * outside a provider then paints the default palette, which is exactly right.
 */
export function useThemeVersion(): number {
  const [version, setVersion] = useState(0);

  useEffect(() => {
    if (typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(() => setVersion((v) => v + 1));
    observer.observe(document.documentElement, {
      attributes: true,
      // `style` because that is where the custom properties land, and the two
      // data attributes because they are what says which skin is applied.
      attributeFilter: ["style", "data-skin", "data-mode"],
    });
    return () => observer.disconnect();
  }, []);

  return version;
}
