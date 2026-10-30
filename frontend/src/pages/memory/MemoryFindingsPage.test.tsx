import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { MemoryFindingsPage } from './MemoryFindingsPage'
import {
  CASE_ID,
  IMAGE_ID,
  envelope,
  failure,
  mockImages,
  mockMemory,
  record,
  renderMemory,
  stamp,
} from './testing'

const ROUTES = <Route index element={<MemoryFindingsPage />} />

/**
 * A tampering envelope in the shape the analysis emits.
 *
 * `TamperingScan::to_json` writes ONE record for the whole capture: the
 * processes it looked at are in `examined`, each carrying its own identity, and
 * that process's signals are in an array inside it. The signals are therefore
 * two levels down, and the process they belong to is on the level between — a
 * signal never carries a pid of its own.
 *
 * A fixture that hoisted `signals` to the top of the record made this page look
 * tested while no real capture could ever reach a signal through it.
 */
function tampering(
  signals: Record<string, unknown>[],
  process: Record<string, unknown> = {
    process: 0xfffff80000000000,
    process_hex: '0xfffff80000000000',
    pid: 712,
    image_file_name: 'lsass.exe',
  },
) {
  return envelope({
    stage: 'tampering',
    record_type: 'MemoryProcessTampering',
    records: [
      record(
        {
          ...stamp(),
          examined: [{ ...process, signals }],
          examined_count: 1,
          signalled_count: signals.length > 0 ? 1 : 0,
          skipped: [],
          skipped_total: 0,
        },
        'tamper-1',
      ),
    ],
  })
}

const HOLLOW = {
  severity: 'critical',
  title: 'PEB image base does not match the VAD image base',
  why: 'The process reports one image base and its address map shows another.',
  not_proof:
    'Some packers and legitimate self-modifying loaders produce the same mismatch.',
  detector: 'tampering.hollow',
  mitre: ['T1055.012'],
}

/**
 * One signal exactly as `TamperSignal::to_json` writes it: a `signal` slug, the
 * `check` that produced it, and a `detail` sentence. No severity, no title, no
 * benign explanation and no process — those are the card's own vocabulary or
 * live on the record.
 */
const WIRE_SIGNAL = {
  signal: 'image_base_mismatch',
  check: 'image_base',
  detail:
    'the loader records the image at 0x7ff6a0000000 in the process’s own memory, and the kernel records having mapped it at 0x7ff6b0000000',
  peb_image_base: 0x7ff6a0000000,
  peb_image_base_hex: '0x7ff6a0000000',
  section_base: 0x7ff6b0000000,
  section_base_hex: '0x7ff6b0000000',
}

describe('MemoryFindingsPage', () => {
  it('shows both the observation and the benign explanation for every signal', async () => {
    mockImages()
    mockMemory('tampering', tampering([HOLLOW]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/The process reports one image base/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Some packers and legitimate self-modifying loaders/),
    ).toBeInTheDocument()
  })

  it('flags a detector that supplied no benign explanation instead of rendering a one-sided card', async () => {
    mockImages()
    mockMemory('tampering', tampering([{ ...HOLLOW, not_proof: undefined }]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/This detector supplied no benign explanation/i),
    ).toBeInTheDocument()
  })

  it('links a signal back to the process it is about', async () => {
    mockImages()
    mockMemory('tampering', tampering([HOLLOW]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByRole('link', { name: 'Open process 712' }),
    ).toHaveAttribute(
      'href',
      `/cases/${CASE_ID}/memory/processes?image=${IMAGE_ID}&pid=712`,
    )
  })

  it('attributes a signal in the shape the analysis really emits to its process', async () => {
    // `TamperSignal::to_json` puts no process on the signal — the process is
    // the `examined` entry the signal sits inside. Reading the signal alone
    // left every real finding as "subject: not stated" with no link back to
    // the process, while the fixtures made the card look correct.
    mockImages()
    mockMemory('tampering', tampering([WIRE_SIGNAL]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByRole('link', { name: 'Open process 712' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/lsass\.exe \(pid 712\)/)).toBeInTheDocument()
    expect(screen.getByText(/the loader records the image at/)).toBeInTheDocument()
    // This producer states no benign explanation, and the card says so rather
    // than presenting a one-sided observation.
    expect(
      screen.getByText(/This detector supplied no benign explanation/i),
    ).toBeInTheDocument()
  })

  it('shows a scan that examined processes and found nothing as empty, not as one nameless finding', async () => {
    // The whole scan arrives as ONE record whose rows are two levels down. Read
    // as a flat list it matched no row key, so the record itself became a row
    // and this lens rendered a card titled "Signal with no title" on every
    // capture — a fabricated finding on the one screen whose output is an
    // accusation, and one that hid the real empty-state copy as well.
    mockImages()
    mockMemory('tampering', tampering([]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText('No tampering signal was recorded'),
    ).toBeInTheDocument()
    expect(screen.queryByText('Signal with no title')).not.toBeInTheDocument()
  })

  it('says the records were unreadable rather than reporting a capture with no signals', async () => {
    // A record whose shape this client does not recognise is an unanswered
    // question. Folding it into the empty list would put it behind the words
    // "the scan ran and recorded nothing", which is exculpatory.
    mockImages()
    mockMemory(
      'tampering',
      envelope({
        stage: 'tampering',
        record_type: 'MemoryProcessTampering',
        records: [record({ ...stamp(), renamed_by_a_future_build: [] }, 'tamper-x')],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByTestId('mem-tamper-unreadable')).toBeInTheDocument()
    expect(
      screen.getByText('No tampering signal could be read'),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(/The tampering scan ran and recorded nothing/i),
    ).toBeNull()
  })

  it('orders the most severe signal first', async () => {
    mockImages()
    mockMemory(
      'tampering',
      tampering([
        { ...HOLLOW, severity: 'low', title: 'A low signal', pid: 1 },
        { ...HOLLOW, severity: 'critical', title: 'A critical signal', pid: 2 },
      ]),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await screen.findByText('A critical signal')
    const headings = screen.getAllByRole('heading', { level: 3 })
    expect(headings[0]).toHaveTextContent('A critical signal')
  })

  it('rates a signal the detector left unrated as unrated rather than as low', async () => {
    mockImages()
    mockMemory('tampering', tampering([{ ...HOLLOW, severity: undefined }]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findAllByText('unrated')).not.toHaveLength(0)
  })

  it('keeps a severity filter in the address so a filtered list can be cited', async () => {
    mockImages()
    mockMemory(
      'tampering',
      tampering([
        { ...HOLLOW, severity: 'low', title: 'A low signal', pid: 1 },
        { ...HOLLOW, severity: 'critical', title: 'A critical signal', pid: 2 },
      ]),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'low' }))
    expect(screen.getByText('A low signal')).toBeInTheDocument()
    expect(screen.queryByText('A critical signal')).not.toBeInTheDocument()
  })

  it('reports a scan that did not run as an error, never as a clean capture', async () => {
    mockImages()
    mockMemory(
      'tampering',
      envelope({
        stage: 'tampering',
        record_type: 'MemoryProcessTampering',
        records: [],
        status: 'failed',
        status_meaning: 'Produced no results at all.',
        record_count: 0,
        failures: [
          failure({ stage: 'tampering', failure: 'the detector set failed to load' }),
        ],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/Tampering signals: this analysis did not run/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByText('No tampering signal was recorded'),
    ).not.toBeInTheDocument()
  })

  it('says an empty scan covers only the checks it performs', async () => {
    mockImages()
    mockMemory(
      'tampering',
      envelope({
        stage: 'tampering',
        record_type: 'MemoryProcessTampering',
        records: [],
        stage_ran: true,
        status: 'complete',
        status_meaning: 'Ran and produced nothing.',
        record_count: 0,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText('No tampering signal was recorded'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/about the checks it performs/i),
    ).toBeInTheDocument()
  })

  it('says a capped list is a floor', async () => {
    mockImages()
    mockMemory(
      'tampering',
      envelope({
        stage: 'tampering',
        record_type: 'MemoryProcessTampering',
        records: [
          record(
            {
              ...stamp(),
              examined: [{ pid: 712, image_file_name: 'lsass.exe', signals: [HOLLOW] }],
              examined_count: 1,
            },
            'tamper-1',
          ),
        ],
        status: 'incomplete',
        count_is_floor: true,
        records_truncated: true,
        record_count: 500,
        records_returned: 1,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/These counts are a floor, not a total/i),
    ).toBeInTheDocument()
  })
})
