/// <reference types="vitest/config" />
import os from 'node:os'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

/**
 * The per-test budget, scaled by how oversubscribed the host already is
 * (UI-023).
 *
 * A vitest timeout is wall-clock. A jsdom test that costs 300 ms of CPU takes
 * 300 ms on an idle host and several seconds on one running twice its cores in
 * other work — the suite then fails on a different test each run, which teaches
 * the person running it to re-run rather than to read.
 *
 * This is NOT "raise the timeout until it stops". The default stays 5 s, which
 * is what CI and an idle workstation get, so a test that is genuinely slow
 * still fails. What the multiplier removes is the part of the elapsed time that
 * is not the test's: the one-minute load average against the core count is a
 * measurement of how much of the host is already spoken for, and the budget is
 * scaled by exactly that, capped at four so a runaway machine cannot turn a
 * hung test into a four-minute wait.
 *
 * `loadavg()` reports zeroes on Windows, which lands on the floor of 1 and the
 * ordinary 5 s. The load is read once, when the config is evaluated — before
 * the suite's own workers start — so it measures the neighbours, not the suite.
 */
function budgetMs(base: number): number {
  const cores = os.availableParallelism?.() ?? os.cpus().length ?? 1
  const [load1] = os.loadavg()
  const contention = Math.min(4, Math.max(1, load1 / Math.max(1, cores)))
  return Math.round(base * contention)
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // Half the cores, not all of them (UI-023). One worker per core is the
    // default, and under it a sibling process saturating the host — a
    // `cargo test --workspace` beside the suite, measured on 2026-09-08 —
    // starved enough jsdom workers to time two tests out at 5 s, on a
    // different test each run. Pinned to half the cores, the same synthetic
    // load (sixteen busy loops) passed every test where the default failed one
    // or two, and the unloaded suite cost 2 s more (40 s against 38 s on
    // sixteen cores). It is a reduction, not a cure: with a workspace
    // `cargo test` AND sixteen busy loops beside it — twice the host's cores
    // in competitors — one 5 s test still times out. The per-test timeout is
    // deliberately NOT raised: that would hide the scheduling problem instead
    // of removing it. Tests that are expensive on their own are made cheap
    // instead (the hex-paging test went from ~13 s to under 2 s by answering
    // sixteen-byte pages).
    maxWorkers: '50%',
    // Two thirds of the files that ran in jsdom never touched a DOM: pure
    // reducers, formatters, normalisers, the contrast instruments. Each still
    // paid for a jsdom environment, which the run summary showed dominating the
    // whole suite. Those files now carry `@vitest-environment node`, which took
    // the environment cost from 240 s to 176 s of summed worker time under a
    // fixed synthetic load, and the wall clock from 96 s to 84 s. Less work is
    // the honest way to be less sensitive to a busy host (UI-023).
    testTimeout: budgetMs(5_000),
    hookTimeout: budgetMs(10_000),
  },
})
