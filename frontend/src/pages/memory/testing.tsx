import type { ReactNode } from 'react'
import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { server } from '../../test/server'
import { MemoryLayout } from './MemoryLayout'
import type {
  MemoryImageSummary,
  StageEnvelope,
  StageFailure,
  StageRecord,
} from './api'

/**
 * Shared harness for the memory-section tests.
 *
 * Every test in this directory renders the real route shell rather than a page
 * in isolation, because the shell is what resolves the capture id — and a lens
 * that reads the wrong capture is the failure mode these tests exist to catch.
 *
 * The fixtures mirror `seance_api/src/memory.rs` field for field. A fixture
 * that drifts from the server is worse than no fixture: it makes a broken
 * client look tested.
 */

export const CASE_ID = 'case-1'
export const IMAGE_ID = 'image-1'

/** A stage envelope for a stage that ran and finished. */
export function envelope(overrides: Partial<StageEnvelope> = {}): StageEnvelope {
  const records = overrides.records ?? []
  return {
    stage: 'processes',
    record_type: 'MemoryProcessList',
    describes: 'The active process list, walked from the kernel process links.',
    per_process: false,
    image_id: IMAGE_ID,
    scoped_to_image: true,
    stage_ran: records.length > 0,
    status: records.length > 0 ? 'complete' : 'did_not_run',
    status_meaning:
      records.length > 0
        ? 'Ran, and every record it produced declared itself complete.'
        : 'Neither a result nor a failure was recorded. Nothing ran.',
    record_count: records.length,
    records_returned: records.length,
    records_truncated: false,
    rows_incomplete: 0,
    rows_completeness_ungraded: 0,
    count_is_floor: false,
    failures: [],
    failures_truncated: false,
    ...overrides,
    records,
  }
}

/** A stage record carrying one analysis blob. */
export function record(
  data: Record<string, unknown>,
  id = 'record-1',
): StageRecord {
  return { id, image_id: IMAGE_ID, data }
}

/** A failure record explaining why a stage did not run. */
export function failure(overrides: Partial<StageFailure> = {}): StageFailure {
  return {
    id: 'failure-1',
    image_id: IMAGE_ID,
    name: 'Memory analysis: a stage did not run',
    stage: 'processes',
    stages: null,
    failure: 'the symbol table was refused',
    pid: null,
    process_name: null,
    profile_evidence: null,
    ...overrides,
  }
}

/** The fields the analysis stamps onto every record it emits. */
export function stamp(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    profile_evidence: 'confirmed',
    symbols_verified: true,
    content_complete: true,
    ...overrides,
  }
}

/** One process, in the tagged-field shape the analysis emits. */
export function processBlob(
  overrides: {
    address?: number
    pid?: number | null
    ppid?: number | null
    name?: string | null
    createTime?: string | null
    exitTime?: string | null
    unreadable?: string[]
  } = {},
): Record<string, unknown> {
  const known = (value: unknown) => ({ kind: 'known', value })
  const unavailable = { kind: 'unavailable', detail: 'page not in the capture' }
  return {
    address: overrides.address ?? 0xfffff80000000000,
    direction: 'forward',
    pid: overrides.pid == null ? unavailable : known(overrides.pid),
    ppid: overrides.ppid == null ? unavailable : known(overrides.ppid),
    image_file_name:
      overrides.name == null ? unavailable : known(overrides.name),
    threads: known(12),
    handles: known(340),
    session_id: known(0),
    wow64: known(false),
    create_time:
      overrides.createTime == null
        ? { kind: 'not_recorded' }
        : {
            kind: 'at',
            filetime: 133000000000000000,
            unix_seconds: 1741684442,
            rfc3339: overrides.createTime,
          },
    exit_time:
      overrides.exitTime == null
        ? { kind: 'not_recorded' }
        : {
            kind: 'at',
            filetime: 133000000000000001,
            unix_seconds: 1741684443,
            rfc3339: overrides.exitTime,
          },
    peb: known(0x7ffd0000),
    has_exited: overrides.exitTime != null,
    unreadable_fields: overrides.unreadable ?? [],
    notes: [],
  }
}

/** A `MemoryProcessList` record's blob. */
export function processListBlob(
  processes: Record<string, unknown>[],
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    head: 0xfffff80000001000,
    links_offset: 0x448,
    count: processes.length,
    complete: true,
    forward_stop: 'wrapped',
    backward_stop: null,
    processes,
    incomplete: [],
    ...stamp(),
    ...overrides,
  }
}

/**
 * One handle, exactly as `HandleRecord::to_json` writes it.
 *
 * The name is an envelope, never a bare string: `{kind:"name", name}` for a
 * named object, `{kind:"unnamed"}` for one that genuinely has none, and
 * `{kind:"unavailable", detail}` when the bytes would not read. A fixture that
 * flattened it made the handle table look tested while every real row rendered
 * "not recorded" (B8-037).
 */
export function handleBlob(
  overrides: {
    objectType?: string
    name?: string
    unavailable?: string
    handleValue?: number
    grantedAccess?: number
  } = {},
): Record<string, unknown> {
  const name =
    overrides.unavailable != null
      ? { kind: 'unavailable', detail: overrides.unavailable }
      : overrides.name != null
        ? { kind: 'name', name: overrides.name }
        : { kind: 'unnamed' }
  return {
    handle_value: overrides.handleValue ?? 0x2f4,
    entry: 0xffffe0000a1b2c30,
    entry_hex: '0xffffe0000a1b2c30',
    object_header: 0xffffe0000a1b2c00,
    object_header_hex: '0xffffe0000a1b2c00',
    body: 0xffffe0000a1b2c40,
    body_hex: '0xffffe0000a1b2c40',
    object_type: overrides.objectType ?? 'File',
    granted_access: overrides.grantedAccess ?? 0x100020,
    name,
    notes: [],
  }
}

/** A `MemoryProcessTree` record's blob. */
export function treeBlob(
  nodes: Record<string, unknown>[],
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return { nodes, ...stamp(), ...overrides }
}

/** One tree node in the analysis's shape. */
export function treeNode(overrides: {
  address?: number
  pid?: number | null
  ppid?: number | null
  parent?: number | null
  children?: number[]
  depth?: number
  link?: { kind: string; detail?: string }
}): Record<string, unknown> {
  return {
    address: overrides.address ?? 0xfffff80000000000,
    pid: overrides.pid ?? null,
    ppid: overrides.ppid ?? null,
    parent: overrides.parent ?? null,
    children: overrides.children ?? [],
    depth: overrides.depth ?? 0,
    link: overrides.link ?? { kind: 'root' },
  }
}

export function image(
  overrides: Partial<MemoryImageSummary> = {},
): MemoryImageSummary {
  return {
    image_id: IMAGE_ID,
    // The evidence the capture was decoded from. Defaulted rather than left to
    // the spread: `Partial` makes it `undefined`-able, and the artifact page
    // matches on it to decide whether to offer the Memory tab at all.
    source_artifact_id: null,
    name: 'WIN10-DESK.mem',
    image_format: 'Windows crash dump',
    architecture: 'X64',
    addressable_bytes: 8 * 1024 * 1024 * 1024,
    file_bytes: 8 * 1024 * 1024 * 1024,
    declared_size: 8 * 1024 * 1024 * 1024,
    size_mismatch: false,
    decode_failed: false,
    content_complete: true,
    content_complete_known: true,
    incomplete: null,
    analysis_state: 'analysed',
    analysis_state_meaning:
      'An image profile was established and the analysis stages ran.',
    profile: {
      record_id: 'profile-1',
      established: true,
      analysed_os: 'windows',
      analysed_by: 'plugin.memory.windows',
      pdb: 'ntkrnlmp.pdb',
      nt_build: 19041,
      weakest_evidence: 'confirmed',
      symbols_verified: true,
      failure: null,
    },
    stage_failures: 0,
    ...overrides,
  }
}

/** Register the capture list the shell needs before any lens renders. */
export function mockImages(images: MemoryImageSummary[] = [image()]) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/memory/images`, () =>
      HttpResponse.json({
        case_id: CASE_ID,
        images,
        image_count: images.length,
        images_truncated: false,
        summaries_complete: true,
      }),
    ),
  )
}

/** Register a JSON handler for one memory endpoint path suffix. */
export function mockMemory(suffix: string, body: unknown, status = 200) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/memory/${suffix}`, () =>
      HttpResponse.json(body as Record<string, unknown>, { status }),
    ),
  )
}

/** The `/coverage` body, with every stage reported as complete by default. */
export function coverageBody(
  stages: { stage: string; status: string; describes?: string }[] = [],
) {
  return {
    case_id: CASE_ID,
    image_id: IMAGE_ID,
    scoped_to_image: true,
    stages: stages.map((s) => ({
      stage: s.stage,
      record_type: 'MemoryRecord',
      describes: s.describes ?? 'A stage.',
      per_process: false,
      stage_ran: s.status !== 'did_not_run',
      status: s.status,
      status_meaning: `status ${s.status}`,
      record_count: s.status === 'complete' ? 1 : 0,
      rows_examined: s.status === 'complete' ? 1 : 0,
      completeness_established_for_all_rows: true,
      rows_incomplete: 0,
      rows_completeness_ungraded: 0,
      count_is_floor: false,
      failures: [],
    })),
    status_by_stage: Object.fromEntries(stages.map((s) => [s.stage, s.status])),
    summary: {
      complete: stages.filter((s) => s.status === 'complete').length,
      incomplete: stages.filter((s) => s.status === 'incomplete').length,
      failed: stages.filter((s) => s.status === 'failed').length,
      did_not_run: stages.filter((s) => s.status === 'did_not_run').length,
      total_stages: stages.length,
    },
    unattributed_failures: [],
    failures_truncated: false,
    coverage_complete: true,
    note: "A stage listed as 'did_not_run' produced neither a result nor a failure.",
  }
}

/**
 * Render the memory shell with the given child routes at the given address.
 *
 * `routes` are real `<Route>` elements, so a test exercises the same nesting
 * the product ships.
 */
export function renderMemory(path: string, routes: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/cases/:caseId/memory" element={<MemoryLayout />}>
            {routes}
          </Route>
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}
