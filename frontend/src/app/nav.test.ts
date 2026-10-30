// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { NAV_SECTIONS, NAV_ITEMS, memoryCountBadge } from './nav'

describe('case sidebar navigation', () => {
  it('groups items into five labelled sections in a principled order', () => {
    expect(NAV_SECTIONS.map((s) => s.section)).toEqual([
      'Overview',
      'Analyse',
      'Evidence',
      'Curate',
      'Admin',
    ])
  })

  it('files Memory under Evidence (it is evidence, not a cross-cutting tool)', () => {
    const sectionOf = (label: string) =>
      NAV_SECTIONS.find((s) => s.items.some((i) => i.label === label))?.section
    expect(sectionOf('Memory')).toBe('Evidence')
    expect(sectionOf('System Info')).toBe('Evidence')
    // Memory must NOT sit with the case-management tools or the cross-cutting
    // analyses — that was the original category error.
    expect(sectionOf('Memory')).not.toBe('Curate')
    expect(sectionOf('Memory')).not.toBe('Admin')
    expect(sectionOf('Memory')).not.toBe('Analyse')
  })

  it('files Duplicates with the analyses, curation tools together, admin at the bottom', () => {
    const sectionOf = (label: string) =>
      NAV_SECTIONS.find((s) => s.items.some((i) => i.label === label))?.section
    expect(sectionOf('Duplicates')).toBe('Analyse')
    expect(sectionOf('Bookmarks')).toBe('Curate')
    expect(sectionOf('Filters')).toBe('Curate')
    expect(sectionOf('Hash Sets')).toBe('Curate')
    expect(sectionOf('Audit Log')).toBe('Admin')
    expect(sectionOf('Settings')).toBe('Admin')
    expect(sectionOf('Help')).toBe('Admin')
  })

  it('puts the five question-shaped surfaces in the rail, not only behind a lens toggle', () => {
    // Communications, Gallery, Map, Execution and the parsed-records index were
    // routed, built and reachable ONLY by noticing the Physical/Logical toggle
    // at the bottom of the sidebar and switching lenses. An examiner inheriting
    // a case does not know that toggle exists, so in practice they reported on
    // a case having never opened half the product.
    const sectionOf = (to: string) =>
      NAV_SECTIONS.find((s) => s.items.some((i) => i.to === to))?.section
    for (const to of ['communications', 'gallery', 'geo', 'execution', 'analysis']) {
      expect(sectionOf(to), `'${to}' is in no rail section`).toBe('Analyse')
    }
  })

  it('labels each of them with the heading its own page carries', () => {
    // The rail, the page heading and a screenshot pasted into a statement have
    // to name the same surface with the same word, or a handover reads as two
    // different screens.
    const labelOf = (to: string) => NAV_ITEMS.find((i) => i.to === to)?.label
    expect(labelOf('communications')).toBe('Communications')
    expect(labelOf('gallery')).toBe('Gallery')
    expect(labelOf('geo')).toBe('Map')
    expect(labelOf('execution')).toBe('Execution')
    // The exception, and the reason for it: the page calls itself "Analysis",
    // which inside a group called "Analyse" says nothing about which of the two
    // it is. Its own subtitle is "Parsed forensic records grouped by type".
    expect(labelOf('analysis')).toBe('Parsed Records')
  })

  it('flattens to EVERY route so the ⌘K palette can never silently drop a group', () => {
    // This guards the CaseLayout command-palette build: it must derive from
    // NAV_ITEMS (the flattened list), not from a single section.
    const routes = NAV_ITEMS.map((i) => i.to)
    const expected = [
      '',
      'findings',
      'timeline',
      'search',
      'communications',
      'gallery',
      'geo',
      'execution',
      'connections',
      'entities',
      'duplicates',
      'analysis',
      'system-info',
      'memory',
      'bookmarks',
      'filters',
      'hash-sets',
      'audit',
      'settings',
      'help',
    ]
    for (const route of expected) {
      expect(routes).toContain(route)
    }
    expect(NAV_ITEMS).toHaveLength(expected.length)
    expect(new Set(routes).size).toBe(routes.length)
  })

  it('gives every item a route and a label, and only Dashboard is an exact-match route', () => {
    for (const item of NAV_ITEMS) {
      expect(item.label.length).toBeGreaterThan(0)
      expect(typeof item.to).toBe('string')
    }
    const exactMatch = NAV_ITEMS.filter((i) => i.end)
    expect(exactMatch.map((i) => i.label)).toEqual(['Dashboard'])
  })
})

describe('memoryCountBadge', () => {
  it('shows the count only when the case holds more than one capture', () => {
    expect(memoryCountBadge(2)).toBe(2)
    expect(memoryCountBadge(7)).toBe(7)
  })

  it('shows nothing for zero or one capture — the shell already makes that clear', () => {
    expect(memoryCountBadge(0)).toBeNull()
    expect(memoryCountBadge(1)).toBeNull()
  })

  it('shows nothing before the count has loaded, never a flash of zero', () => {
    expect(memoryCountBadge(undefined)).toBeNull()
  })
})
