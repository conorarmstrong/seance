import { SKINS, SKIN_IDS, type Mode } from "./palettes";
import { decode, encode } from "./applyTheme";
import { useTheme } from "./ThemeProvider";

const MODES: Mode[] = ["light", "dark"];

/**
 * The compact theme control, for the Cases list header.
 *
 * The full picker with its swatches lives in case settings, which is only
 * reachable once a case is open — so without this an examiner who finds the
 * default hard to read would have to open somebody's case to fix it. This is
 * the same setting, one control wide.
 *
 * A real `<select>`, deliberately: it is keyboard-reachable and screen-reader
 * announced with no popup logic of this product's own, and its own popup
 * follows the theme because `applyTheme` sets `color-scheme` — which is the
 * point of setting it.
 */
export function ThemeSelect() {
  const { theme, setTheme } = useTheme();

  return (
    <label className="tsel">
      <span className="sr-only">Theme</span>
      <select
        className="tsel-select"
        value={theme === null ? "" : encode(theme)}
        onChange={(e) =>
          setTheme(e.target.value === "" ? null : decode(e.target.value))
        }
        aria-label="Theme"
      >
        <option value="">Séance (default)</option>
        {SKIN_IDS.map((id) =>
          MODES.map((mode) => (
            <option key={`${id}:${mode}`} value={`${id}:${mode}`}>
              {SKINS[id].name} — {mode}
            </option>
          )),
        )}
      </select>
    </label>
  );
}
