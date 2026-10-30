// @vitest-environment node
import { describe, it } from "vitest";
import { contrastRatio, flatten } from "../app/composedContrast";
import { SKINS, SKIN_IDS } from "./palettes";

describe("rank the light palettes", () => {
  it("prints headroom", () => {
    const rows: string[] = [];
    for (const id of SKIN_IDS) {
      const p = SKINS[id].light;
      const surfaces = [p["bg-0"], p["bg-1"], p["bg-2"], p["bg-3"]];
      const tints = [
        p["accent-bg"],
        p["ok-bg"],
        p["warn-bg"],
        p["danger-bg"],
        p["info-bg"],
      ];
      const grounds: string[] = [...surfaces];
      for (const t of tints)
        for (const s of surfaces)
          grounds.push(
            flatten(
              {
                hex: t.replace(/rgba?\(([^)]+)\)/, (_m, v) => {
                  const [r, g, b] = v
                    .split(",")
                    .map((x: string) => Number(x.trim()));
                  return `#${[r, g, b].map((n: number) => n.toString(16).padStart(2, "0")).join("")}`;
                }),
                alpha: 0.12,
              },
              s,
            ),
          );
      const inks = [
        ["text-0", p["text-0"]],
        ["text-1", p["text-1"]],
        ["text-2", p["text-2"]],
        ["accent", p.accent],
        ["ok", p.ok],
        ["warn", p.warn],
        ["danger", p.danger],
        ["info", p.info],
      ] as const;
      let min = 99;
      let minAt = "";
      const ratios: number[] = [];
      for (const [name, ink] of inks) {
        for (const g of grounds) {
          const r = contrastRatio(ink, g);
          ratios.push(r);
          if (r < min) {
            min = r;
            minAt = `${name} on ${g}`;
          }
        }
      }
      ratios.sort((a, b) => a - b);
      const median = ratios[Math.floor(ratios.length / 2)];
      const text0 = contrastRatio(p["text-0"], p["bg-0"]);
      rows.push(
        `${id.padEnd(7)} min ${min.toFixed(2)} (${minAt})  median ${median.toFixed(2)}  text-0/bg-0 ${text0.toFixed(2)}  bg-0 ${p["bg-0"]}`,
      );
    }
    console.log("\n" + rows.join("\n"));
  });
});
