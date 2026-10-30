import { SKINS, SKIN_IDS, type Mode, type SkinId } from "./palettes";
import { paletteFor } from "./applyTheme";
import { useTheme } from "./ThemeProvider";
import "./themes.css";

const MODES: Mode[] = ["light", "dark"];

/**
 * A swatch of what a palette looks like: its surface, its text ladder, its
 * accent and its three semantic inks.
 *
 * Drawn from the palette's own values rather than by applying it, so the
 * examiner can compare all ten without the page changing under them. The
 * inline styles are the one place in this product where a colour is set in JS,
 * and they are values read straight out of the gated palette — not a second
 * copy of it.
 */
function Swatch({ skin, mode }: { skin: SkinId; mode: Mode }) {
  const palette = paletteFor({ skin, mode });
  return (
    <span
      className="tp-swatch"
      style={{
        background: palette["bg-1"],
        borderColor: palette["border-1"],
      }}
      aria-hidden="true"
    >
      <span className="tp-bar" style={{ background: palette["text-0"] }} />
      <span
        className="tp-bar tp-bar-mid"
        style={{ background: palette["text-1"] }}
      />
      <span
        className="tp-bar tp-bar-low"
        style={{ background: palette["text-2"] }}
      />
      <span className="tp-dot" style={{ background: palette.accent }} />
      <span className="tp-dot" style={{ background: palette.ok }} />
      <span className="tp-dot" style={{ background: palette.warn }} />
      <span className="tp-dot" style={{ background: palette.danger }} />
    </span>
  );
}

/**
 * Choose a skin.
 *
 * Every option is a real `<button>` inside a `<fieldset>` with a legend, so the
 * group announces itself and each choice is reachable by keyboard without a
 * roving-tabindex of its own — this is a list of controls, not a data table.
 *
 * The chosen option carries `aria-pressed`, not a colour alone: which theme is
 * active must be readable by something that cannot see the highlight.
 */
export function ThemePicker() {
  const { theme, setTheme, saveFailed } = useTheme();

  return (
    <div className="tp">
      {saveFailed && (
        <p className="error-note" role="alert">
          The theme is applied for this session but could not be saved to your
          account, so signing in elsewhere — or here tomorrow — will show the
          previous one. This is a failed request, not a rejected choice.
        </p>
      )}

      <fieldset className="tp-group">
        <legend className="tp-legend">Theme</legend>
        <div className="tp-options">
          <button
            type="button"
            className="tp-option"
            aria-pressed={theme === null}
            onClick={() => setTheme(null)}
          >
            <span className="tp-swatch tp-swatch-default" aria-hidden="true">
              <span className="tp-bar" />
              <span className="tp-bar tp-bar-mid" />
              <span className="tp-bar tp-bar-low" />
              <span className="tp-dot" />
            </span>
            <span className="tp-label">
              <span className="tp-name">Default</span>
              <span className="tp-desc">
                What this build ships with — Opus in daylight — and what you
                keep following if it changes. Choosing Opus light below is a
                different answer: it pins the palette, this one tracks the
                default.
              </span>
            </span>
          </button>

          {SKIN_IDS.map((id) =>
            MODES.map((mode) => {
              const active = theme?.skin === id && theme?.mode === mode;
              return (
                <button
                  key={`${id}:${mode}`}
                  type="button"
                  className="tp-option"
                  aria-pressed={active}
                  onClick={() => setTheme({ skin: id, mode })}
                >
                  <Swatch skin={id} mode={mode} />
                  <span className="tp-label">
                    <span className="tp-name">
                      {SKINS[id].name} <span className="tp-mode">{mode}</span>
                    </span>
                    <span className="tp-desc">{SKINS[id].description}</span>
                  </span>
                </button>
              );
            }),
          )}
        </div>
      </fieldset>

      <p className="tp-note">
        Your choice is stored against your account, not this browser, so it
        follows you to another workstation. Every theme is held to the same WCAG
        AA contrast floor as the default — the palettes are measured in the test
        suite, not reviewed by eye — so none of them makes a screen harder to
        read than the one it replaces.
      </p>
    </div>
  );
}
