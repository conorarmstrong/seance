# Seance Web UI

React + TypeScript single-page app for the Seance digital forensics
platform. Replaces the previous Askama/HTMX GUI.

## Development

Start the API server (from the repo root):

```sh
cargo run -p seance_cli -- --headless
```

Then run the Vite dev server:

```sh
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` to `http://127.0.0.1:8080`, so auth cookies
and SSE work same-origin. Sign in with the credentials printed in the
server banner (default `admin` / `seance`).

## Production build

```sh
npm --prefix frontend run build
```

The server serves `frontend/dist` automatically (configurable with
`--web-root`); client-side routes fall back to `index.html`. Run with
`--headless` to disable the UI entirely.

## Tests

```sh
npm test          # vitest run — a single pass
npm run typecheck # tsc -b
npm run lint      # oxlint
npx vitest        # watch mode while iterating
```

Run your own directory while iterating (`npx vitest run src/pages/<dir>`) and the
full pass before finishing.

Two things in `vite.config.ts` exist because several agents and people share the
build machine. The pool is pinned to **half** the cores, and the
per-test budget is the 5-second default **multiplied by the host's measured
contention** — the one-minute load average over the core count, capped at four,
read once before the suite's own workers start. On an idle machine and in CI that
multiplier is 1, so a genuinely slow test fails exactly where it always did; on a
machine already running twice its cores in other work it stops charging another
process's time to whichever test happens to be running.

A test file that touches no DOM carries `@vitest-environment node` and skips the
jsdom setup entirely. Thirty-two do. Keep new ones that way: if the file needs a
DOM the node environment fails immediately and tells you.

Some assertions are locale-sensitive (dates, number grouping), so the suite is
also run under a non-English locale:

```sh
LC_ALL=de_DE.UTF-8 npm test
```

Tests use Vitest, React Testing Library, and MSW for API mocking. See
`CONVENTIONS.md` for the design system and code conventions.

Two suites are worth knowing about before you touch colour or the help page,
because both are gates rather than advice:

- `src/app/contrast.test.ts` measures every colour pairing in every stylesheet
  under `src/`, as composited on screen, against the WCAG AA floor.
- `src/pages/help/help-coverage.test.ts` fails the build when a parser plugin or
  container crate ships undocumented, or when a documented one is removed;
  `src/pages/help/HelpPage.test.tsx` pins the specific claims that have been
  wrong before. `src/pages/help/HELP_SYNC.md` explains how the online help is
  kept true — read it before editing `HelpPage.tsx`.

All fonts are bundled via @fontsource — the UI has no CDN or network
dependencies, so it works on air-gapped examination workstations.
