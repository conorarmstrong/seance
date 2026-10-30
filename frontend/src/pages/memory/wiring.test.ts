// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
/// <reference types="node" />
// This test reads the source tree (node fs/path); the reference pulls in Node
// typings for this file only, since the app tsconfig is DOM-scoped.
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Wiring guard for the memory section.
 *
 * This exists because of a specific incident: an entire analysis tier was
 * written, unit-tested and committed while the one function that dispatched it
 * returned nothing. Every test passed and none of the code ever ran. Component
 * tests cannot catch that — they render the component directly, which is
 * exactly the call the product never makes.
 *
 * So this test asserts the seam instead of the behaviour: every lens in this
 * directory is registered on a route, that route hangs off the case shell, and
 * the shell carries a nav entry that reaches it. A page nobody can navigate to
 * fails here rather than shipping as a finished feature.
 */

/** Walk up from the working directory to the frontend package root. */
function findFrontendRoot(): string {
  let dir = process.cwd()
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, 'src', 'pages', 'memory'))) return dir
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  throw new Error('could not locate the frontend root (no src/pages/memory)')
}

const frontendRoot = findFrontendRoot()
const memoryDir = path.join(frontendRoot, 'src', 'pages', 'memory')
const appDir = path.join(frontendRoot, 'src', 'app')
const routesSrc = fs.readFileSync(path.join(appDir, 'routes.tsx'), 'utf8')
const layoutSrc = fs.readFileSync(path.join(appDir, 'CaseLayout.tsx'), 'utf8')
const navSrc = fs.readFileSync(path.join(appDir, 'nav.ts'), 'utf8')
const commandsSrc = fs.readFileSync(path.join(appDir, 'commands.ts'), 'utf8')

/** Every source file in this directory that is not a test or a test helper. */
function sourceFiles(): string[] {
  return fs
    .readdirSync(memoryDir)
    .filter(
      (name: string) =>
        (name.endsWith('.tsx') || name.endsWith('.ts')) &&
        !name.endsWith('.test.tsx') &&
        !name.endsWith('.test.ts') &&
        name !== 'testing.tsx',
    )
    .sort()
}

/** The lens routes this section is expected to expose, path → component. */
const LENS_ROUTES: [string, string][] = [
  ['index', 'MemoryOverviewPage'],
  ['image', 'ImageProfilePage'],
  ['processes', 'ProcessTreePage'],
  ['network', 'MemoryNetworkPage'],
  ['handles', 'MemoryHandlesPage'],
  ['system', 'MemorySystemPage'],
  ['credentials', 'MemoryCredentialsPage'],
  ['findings', 'MemoryFindingsPage'],
]

describe('memory section wiring', () => {
  it('registers the memory shell as a child route of the case layout', () => {
    expect(routesSrc).toMatch(/<Route path="memory" element=\{<MemoryLayout \/>\}>/)
    expect(routesSrc).toContain("'../pages/memory/MemoryLayout'")
  })

  it('registers a route for every lens, so none of them is unreachable', () => {
    for (const [routePath, component] of LENS_ROUTES) {
      const element = `element={<${component} />}`
      expect(routesSrc, `${component} is not on a route`).toContain(element)
      if (routePath === 'index') {
        expect(routesSrc).toContain(`<Route index ${element} />`)
      } else {
        expect(routesSrc).toContain(`<Route path="${routePath}" ${element} />`)
      }
      expect(
        routesSrc,
        `${component} has no lazy import`,
      ).toContain(`'../pages/memory/${component}'`)
    }
  })

  it('puts a Memory entry in the case navigation, so the section can be reached by clicking', () => {
    // The nav lives in its own module now; the Memory entry must be there.
    expect(navSrc).toMatch(/\{\s*to:\s*'memory',\s*label:\s*'Memory'/)
    // The command palette's destination list is built from the flattened
    // NAV_ITEMS, so this one entry also makes "Go to Memory" available without a
    // second registration. Deriving from NAV_ITEMS (not a section, and not a
    // hand-kept second list) is what keeps every group reachable from the
    // palette. The list moved out of CaseLayout into its own module; the shell
    // must still be the thing that mounts it.
    expect(commandsSrc).toContain('Go to ${dest.label}')
    expect(commandsSrc).toMatch(/NAV_ITEMS\.map/)
    expect(layoutSrc).toMatch(/buildCaseCommands\(caseId/)
  })

  it('leaves no component in this directory that nothing imports', () => {
    const files = sourceFiles()
    const bodies = new Map<string, string>(
      files.map((name: string) => [
        name,
        fs.readFileSync(path.join(memoryDir, name), 'utf8'),
      ]),
    )
    // Entry points: reached from the router rather than from a sibling.
    const entryPoints = new Set([
      'MemoryLayout.tsx',
      ...LENS_ROUTES.map(([, component]) => `${component}.tsx`),
    ])

    const orphans: string[] = []
    for (const name of files) {
      if (entryPoints.has(name)) continue
      const moduleName = name.replace(/\.tsx?$/, '')
      const importedBySibling = files.some(
        (other: string) =>
          other !== name && bodies.get(other)!.includes(`'./${moduleName}'`),
      )
      const importedByRouter = routesSrc.includes(`/memory/${moduleName}'`)
      if (!importedBySibling && !importedByRouter) orphans.push(name)
    }

    expect(
      orphans,
      `nothing imports these, so nothing runs them:\n  ${orphans.join('\n  ')}`,
    ).toEqual([])
  })

  it('imports the section stylesheet somewhere, so the lenses are not unstyled', () => {
    const importsCss = sourceFiles().some((name: string) =>
      fs.readFileSync(path.join(memoryDir, name), 'utf8').includes("'./memory.css'"),
    )
    expect(importsCss).toBe(true)
  })
})
