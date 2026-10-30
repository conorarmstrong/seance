import { describe, expect, it, vi } from 'vitest'

import { rankCommands } from '../components/CommandPalette'
import {
  CASE_DESTINATIONS,
  buildCaseCommands,
  destinationPath,
} from './commands'
import { NAV_ITEMS } from './nav'

/** The command a palette build produced for a destination path. */
function commandFor(commands: ReturnType<typeof buildCaseCommands>, to: string) {
  const dest = CASE_DESTINATIONS.find((d) => d.to === to)
  expect(dest, `no destination for '${to}'`).toBeDefined()
  return commands.find((c) => c.label === `Go to ${dest!.label}`)
}

describe('CASE_DESTINATIONS', () => {
  it('covers every nav-rail item, so the rail and the palette can never disagree', () => {
    // The rail and the palette are two of the three ways every surface must be
    // reachable. Deriving the palette from a hand-written list that has drifted
    // from the rail is the exact failure this pins.
    for (const item of NAV_ITEMS) {
      const dest = CASE_DESTINATIONS.find((d) => d.to === item.to)
      expect(dest, `nav item '${item.label}' has no palette destination`).toBeDefined()
      expect(dest!.label).toBe(item.label)
    }
  })

  it('adds the addressable views that are deliberately not rail rows', () => {
    // The videos and audio galleries are real, separately addressable views
    // reachable only from the Logical navigator. Three near-identical rail rows
    // would be worse than one, but a palette with no way to say "videos" leaves
    // them undiscoverable.
    const extra = CASE_DESTINATIONS.filter(
      (d) => !NAV_ITEMS.some((i) => i.to === d.to),
    ).map((d) => d.to)
    expect(extra).toEqual(['gallery?kind=videos', 'gallery?kind=audio'])
  })

  it('gives one address per destination', () => {
    const paths = CASE_DESTINATIONS.map((d) => d.to)
    expect(new Set(paths).size).toBe(paths.length)
    const labels = CASE_DESTINATIONS.map((d) => d.label)
    expect(new Set(labels).size).toBe(labels.length)
  })

  it('answers the words an examiner actually says, not the route spelling', () => {
    // Each of these was typed into the palette during review and returned "No
    // matches", because matching ran against the route-shaped label alone.
    const spoken: [string, string][] = [
      ['chats', 'communications'],
      ['messages', 'communications'],
      ['calls', 'communications'],
      ['whatsapp', 'communications'],
      ['pictures', 'gallery'],
      ['photos', 'gallery'],
      ['gps', 'geo'],
      ['location', 'geo'],
      ['prefetch', 'execution'],
      ['programs', 'execution'],
      ['ram', 'memory'],
      ['dupes', 'duplicates'],
      ['starred', 'bookmarks'],
      ['shortcuts', 'help'],
    ]
    for (const [word, to] of spoken) {
      const dest = CASE_DESTINATIONS.find((d) => d.to === to)
      expect(dest, `no destination '${to}'`).toBeDefined()
      expect(
        dest!.keywords,
        `'${word}' does not reach ${dest!.label}`,
      ).toContain(word)
    }
  })

  it('never lets an alias be another destination’s name', () => {
    // An alias may legitimately be shared -- "media" should surface Gallery,
    // Videos and Audio together. What must never happen is an alias that IS
    // another view's name, because then typing the name of one view ranks a
    // different view above it.
    const names = new Set(CASE_DESTINATIONS.map((d) => d.label.toLowerCase()))
    for (const dest of CASE_DESTINATIONS) {
      expect(new Set(dest.keywords).size, `${dest.label} repeats an alias`).toBe(
        dest.keywords.length,
      )
      for (const word of dest.keywords) {
        if (word === dest.label.toLowerCase()) continue
        expect(names.has(word), `'${word}' is the name of another view`).toBe(false)
      }
    }
  })
})

describe('what the palette answers when an examiner types', () => {
  // The unit that matters is not "does this word match" but "is the view they
  // meant the row Enter would take". Scored against the REAL destination list,
  // because a query scavenges letters out of unrelated labels more often than
  // invented test labels suggest: "gps" appears, in order, inside "Go to Parsed
  // Records", and shipped one build ranking the records index above the map.
  const answers: [string, string][] = [
    ['chats', 'Communications'],
    ['messages', 'Communications'],
    ['whatsapp', 'Communications'],
    ['calls', 'Communications'],
    ['photos', 'Gallery'],
    ['pictures', 'Gallery'],
    ['gps', 'Map'],
    ['location', 'Map'],
    ['geo', 'Map'],
    ['prefetch', 'Execution'],
    ['programs', 'Execution'],
    ['ram', 'Memory'],
    ['dupes', 'Duplicates'],
    ['starred', 'Bookmarks'],
    ['nsrl', 'Hash Sets'],
    ['video', 'Videos'],
    ['voicemail', 'Audio'],
    // The names themselves still have to win, aliases or no aliases.
    ['timeline', 'Timeline'],
    ['search', 'Search'],
    ['communications', 'Communications'],
    ['gallery', 'Gallery'],
    ['memory', 'Memory'],
    ['help', 'Help'],
  ]

  it('puts the view the word means first', () => {
    const commands = buildCaseCommands('c1', () => {})
    for (const [typed, expected] of answers) {
      const ranked = rankCommands(commands, typed)
      expect(ranked[0]?.label, `'${typed}' ranked ${ranked[0]?.label}`).toBe(
        `Go to ${expected}`,
      )
    }
  })

  it('says which alias matched, and says nothing extra when the name matched', () => {
    const commands = buildCaseCommands('c1', () => {})
    expect(rankCommands(commands, 'whatsapp')[0].hint).toBe('whatsapp')
    expect(rankCommands(commands, 'communications')[0].hint).toBeUndefined()
  })
})

describe('destinationPath', () => {
  it('resolves a destination against the case it belongs to', () => {
    expect(destinationPath('abc', 'timeline')).toBe('/cases/abc/timeline')
    expect(destinationPath('abc', 'gallery?kind=videos')).toBe(
      '/cases/abc/gallery?kind=videos',
    )
  })

  it('resolves the dashboard to the case root, not to a trailing slash', () => {
    // `/cases/abc/` and `/cases/abc` are the same view under two addresses,
    // which is the ambiguity this whole change exists to remove.
    expect(destinationPath('abc', '')).toBe('/cases/abc')
  })
})

describe('buildCaseCommands', () => {
  it('navigates to the destination the label names', () => {
    const navigate = vi.fn()
    const commands = buildCaseCommands('case-1', navigate)

    commandFor(commands, 'communications')?.run()
    expect(navigate).toHaveBeenLastCalledWith('/cases/case-1/communications')

    commandFor(commands, 'gallery?kind=audio')?.run()
    expect(navigate).toHaveBeenLastCalledWith('/cases/case-1/gallery?kind=audio')

    commandFor(commands, '')?.run()
    expect(navigate).toHaveBeenLastCalledWith('/cases/case-1')
  })

  it('carries the aliases through to the palette', () => {
    const commands = buildCaseCommands('case-1', vi.fn())
    const comms = commandFor(commands, 'communications')
    expect(comms?.keywords).toContain('chats')
  })

  it('gives every command a distinct id so the list can be keyed', () => {
    const ids = buildCaseCommands('case-1', vi.fn()).map((c) => c.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('ends with the case-independent action, not with a destination', () => {
    const commands = buildCaseCommands('case-1', vi.fn())
    const last = commands[commands.length - 1]
    expect(last.label).toBe('Switch case')
    const navigate = vi.fn()
    buildCaseCommands('case-1', navigate)[commands.length - 1].run()
    expect(navigate).toHaveBeenCalledWith('/')
  })
})
