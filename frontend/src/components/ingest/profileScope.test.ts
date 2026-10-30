// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import type { IngestionProfile } from '../../api/types'
import {
  groupModules,
  moduleNamespace,
  namespaceLabel,
  profileScope,
  resolveProfileGovernance,
} from './profileScope'

const REGISTRY = [
  'plugin.ntfs.mft_parser',
  'plugin.windows.registry_parser',
  'plugin.browsers.history_parser',
  'plugin.messaging.whatsapp',
  'plugin.email.parser',
  'plugin.fs.ext4',
  'plugin.filesystem.apfs',
  'plugin.search.indexer',
]

describe('profileScope', () => {
  it('reports every registered module as running when the enabled list is empty', () => {
    // Mirrors `IngestionProfile::should_run_module`: an empty enabled list is
    // "run everything", not "run nothing".
    const scope = profileScope(
      { enabled_modules: [], disabled_modules: [] },
      REGISTRY,
    )
    expect(scope.runs).toEqual(REGISTRY)
    expect(scope.skips).toEqual([])
    expect(scope.registered).toBe(REGISTRY.length)
    expect(scope.restricts).toBe(false)
  })

  it('names the registered modules an enabled list leaves out', () => {
    const scope = profileScope(
      {
        enabled_modules: ['plugin.ntfs.mft_parser', 'plugin.search.indexer'],
        disabled_modules: [],
      },
      REGISTRY,
    )
    expect(scope.runs).toEqual([
      'plugin.ntfs.mft_parser',
      'plugin.search.indexer',
    ])
    expect(scope.skips).toContain('plugin.browsers.history_parser')
    expect(scope.skips).toContain('plugin.messaging.whatsapp')
    expect(scope.skips).toContain('plugin.email.parser')
    expect(scope.skips).toHaveLength(6)
    expect(scope.restricts).toBe(true)
  })

  it('lets an explicit disable beat the enabled list', () => {
    const scope = profileScope(
      {
        enabled_modules: ['plugin.ntfs.mft_parser', 'plugin.search.indexer'],
        disabled_modules: ['plugin.search.indexer'],
      },
      REGISTRY,
    )
    expect(scope.runs).toEqual(['plugin.ntfs.mft_parser'])
    expect(scope.skips).toContain('plugin.search.indexer')
  })

  it('disables from a whole-registry profile too', () => {
    const scope = profileScope(
      { enabled_modules: [], disabled_modules: ['plugin.email.parser'] },
      REGISTRY,
    )
    expect(scope.runs).not.toContain('plugin.email.parser')
    expect(scope.skips).toEqual(['plugin.email.parser'])
    expect(scope.restricts).toBe(true)
  })

  it('separates modules the profile names that this build does not register', () => {
    // The server warns about these into a log nobody reads. A named module the
    // build has no code for cannot run, and counting it under "runs" would
    // overstate what the ingest will do.
    const scope = profileScope(
      {
        enabled_modules: ['plugin.ntfs.mft_parser', 'plugin.gone.away'],
        disabled_modules: [],
      },
      REGISTRY,
    )
    expect(scope.runs).toEqual(['plugin.ntfs.mft_parser'])
    expect(scope.unregistered).toEqual(['plugin.gone.away'])
  })
})

describe('groupModules', () => {
  it('groups by module namespace, largest group first', () => {
    const groups = groupModules([
      'plugin.messaging.whatsapp',
      'plugin.messaging.signal',
      'plugin.email.parser',
    ])
    expect(groups[0].label).toBe(namespaceLabel('plugin.messaging'))
    expect(groups[0].ids).toEqual([
      'plugin.messaging.signal',
      'plugin.messaging.whatsapp',
    ])
    expect(groups[1].ids).toEqual(['plugin.email.parser'])
  })

  it('merges the two filesystem namespaces under one label', () => {
    // `plugin.fs.*` and `plugin.filesystem.*` are the same thing to an
    // examiner; two headings reading "Filesystems" would suggest two kinds.
    const groups = groupModules(['plugin.fs.ext4', 'plugin.filesystem.apfs'])
    expect(groups).toHaveLength(1)
    expect(groups[0].ids).toEqual(['plugin.filesystem.apfs', 'plugin.fs.ext4'])
  })

  it('shows an unrecognised namespace verbatim rather than dropping it', () => {
    const groups = groupModules(['plugin.newthing.parser'])
    expect(groups[0].label).toBe('plugin.newthing')
    expect(groups[0].ids).toEqual(['plugin.newthing.parser'])
  })

  it('reads a two-part module id as its own namespace', () => {
    expect(moduleNamespace('macos.tcc')).toBe('macos')
    expect(moduleNamespace('container.e01_reader')).toBe('container')
    expect(moduleNamespace('plugin.ntfs.mft_parser')).toBe('plugin.ntfs')
  })
})

const PROFILE = (over: Partial<IngestionProfile> = {}): IngestionProfile => ({
  id: 'p-1',
  case_id: 'case-1',
  name: 'triage',
  description: 'Fast triage mode - essential artifacts only',
  enabled_modules: ['plugin.ntfs.mft_parser'],
  disabled_modules: [],
  is_active: true,
  created_at: 1700000000,
  ...over,
})

describe('resolveProfileGovernance', () => {
  it('reads the empty option as the case profile already in force, not as "all modules"', () => {
    // The empty option does not clear anything: the server only touches the
    // active profile when the request names one, so leaving the select alone
    // ingests under whatever profile a previous ingest activated.
    const active = PROFILE()
    const governance = resolveProfileGovernance({
      selection: '',
      profiles: [active],
      active,
      registry: REGISTRY,
    })
    expect(governance.kind).toBe('profile')
    if (governance.kind !== 'profile') throw new Error('unreachable')
    expect(governance.profile.name).toBe('triage')
    expect(governance.scope?.restricts).toBe(true)
    expect(governance.inherited).toBe(true)
  })

  it('says no profile is in force when the case has none', () => {
    expect(
      resolveProfileGovernance({
        selection: '',
        profiles: [],
        active: null,
        registry: REGISTRY,
      }),
    ).toEqual({ kind: 'none' })
  })

  it('resolves a built-in name to the record the case already holds', () => {
    const triage = PROFILE({ is_active: false })
    const governance = resolveProfileGovernance({
      selection: 'triage',
      profiles: [triage],
      active: null,
      registry: REGISTRY,
    })
    expect(governance.kind).toBe('profile')
    if (governance.kind !== 'profile') throw new Error('unreachable')
    expect(governance.inherited).toBe(false)
    expect(governance.scope?.skips).toContain('plugin.browsers.history_parser')
  })

  it('reports a built-in this case has never recorded rather than describing it', () => {
    // Nothing the frontend can read says what the server's built-in profiles
    // contain until one exists on the case, and inventing the list here is how
    // a screen ends up describing a scoping decision it cannot see.
    expect(
      resolveProfileGovernance({
        selection: 'triage',
        profiles: [],
        active: null,
        registry: REGISTRY,
      }),
    ).toEqual({ kind: 'unrecorded', name: 'triage' })
  })

  it('keeps the profile but drops the scope when the module registry is unreadable', () => {
    const governance = resolveProfileGovernance({
      selection: 'triage',
      profiles: [PROFILE()],
      active: null,
      registry: undefined,
    })
    expect(governance.kind).toBe('profile')
    if (governance.kind !== 'profile') throw new Error('unreachable')
    expect(governance.scope).toBeNull()
  })

  it('refuses to answer while the lists it would answer from are missing', () => {
    expect(
      resolveProfileGovernance({
        selection: '',
        profiles: [],
        active: undefined,
        registry: REGISTRY,
      }),
    ).toEqual({ kind: 'unreadable', what: 'active profile' })
    expect(
      resolveProfileGovernance({
        selection: 'triage',
        profiles: undefined,
        active: null,
        registry: REGISTRY,
      }),
    ).toEqual({ kind: 'unreadable', what: 'profile list' })
  })
})
