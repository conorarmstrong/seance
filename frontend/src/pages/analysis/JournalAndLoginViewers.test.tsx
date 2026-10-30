import { render, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { RecordsViewerPage } from './RecordsViewerPage'
import { VIEWERS } from './viewers'
import { humanizeType } from './lib'

/**
 * The tailored viewers added for record classes that previously fell through to
 * a generic key/value table.
 *
 * Why these matter beyond tidiness: the two NTFS journals are the largest record
 * classes a Windows case produces, and a USN reason bitmask or an LSN in a
 * generic table cannot be grouped, sorted or read at all. The utmp family is
 * how a Linux intrusion is argued — a failed-login burst from one host is the
 * finding, and it is invisible as unordered key/value blobs.
 */

const CASE_ID = 'case-1'

function mockRecords(type: string, records: ParsedRecord[]) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const requested = url.searchParams.get('type') ?? ''
      const all = requested === type ? records : []
      return HttpResponse.json({
        records: all,
        total: all.length,
        page: 1,
        page_size: 50,
        type: requested,
      })
    }),
  )
}

function rec(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return { id, parent_id: `a-${id}`, artifact_type: 'ParsedRecord', metadata }
}

function renderViewer(type: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${type}`]}>
        <Routes>
          <Route
            path="/cases/:caseId/analysis/:type"
            element={<RecordsViewerPage />}
          />
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('viewer coverage', () => {
  // The Analysis index badges an unregistered type "generic view". These are
  // the classes that were carrying that badge and should no longer.
  const NEWLY_TAILORED = [
    'UsnJournalEntry',
    'NtfsLogFileRecord',
    'BrowserCookie',
    'BrowserLogin',
    'BrowserAutofill',
    'BrowserSession',
    'YaraMatch',
    'LoginSession',
    'FailedLogin',
    'BootEvent',
    'LastLogin',
    // macOS's login history, which lives in the audit trail rather than in
    // any login-accounting file.
    'AuditEvent',
    // The keychain's cleartext index: which services and accounts the person
    // held credentials for, with every secret marked locked.
    'KeychainItem',
    // An iOS backup's keychain (HUNT-111): attributes in the clear, the
    // secret withheld, the ThisDeviceOnly items marked unreadable.
    'IosKeychainItem',
    // The Apple System Log store, where macOS's wtmpx went.
    'AslMessage',
    // The devices the Apple ID's keychain circle held, which may include
    // devices the evidence does not contain.
    'ICloudKeychainDevice',
    // The packet-capture protocol views. HTTP was the worst of these: the
    // method, the status and the posted form fields are three levels down
    // inside two nested objects, so the generic flat table showed none of
    // them. Their own assertions are in PcapProtocolViewers.test.tsx.
    'HttpTransaction',
    'TlsSession',
    'TlsCertificate',
    'ArpBinding',
    // The NetworkList profiles, whose two time columns have to distinguish an
    // instant from a local time with no zone.
    'NetworkProfile',
    // The wireless profiles: four key states that rendered as four identical
    // rows on the generic table.
    'WifiNetwork',
    // Spotlight's indexed items and its two vocabularies. The items need a
    // path column and the file's own dates; the content types need the
    // caution that the index knowing a type is not a file being present.
    'SpotlightItem',
    'SpotlightProperty',
    'SpotlightContentType',
    // The unified log's catalogue: an inventory of the code that logs, whose
    // screen has to keep saying that a catalogue entry is not execution.
    'UnifiedLogImage',
    // The log's own messages and its per-file record.
    'UnifiedLogMessage',
    'UnifiedLog',
    // The registry MRUs: the path is an array and the generic table skips
    // nested values, so the one field read out of the format was invisible.
    'ShellMruEntry',
  ]

  it('registers a tailored viewer for each newly covered record class', () => {
    for (const type of NEWLY_TAILORED) {
      expect(VIEWERS[type], `${type} has no tailored viewer`).toBeDefined()
    }
  })

  it('spells the acronyms in these type names rather than title-casing them', () => {
    // "Usn Journal" and "Yara Match" are not what these artefacts are called,
    // and an examiner scanning the Analysis index reads the label, not the key.
    expect(humanizeType('UsnJournalEntry')).toContain('USN')
    expect(humanizeType('NtfsLogFileRecord')).toContain('NTFS')
    expect(humanizeType('YaraMatch')).toContain('YARA')
  })
})

describe('UsnJournalEntry viewer', () => {
  it('shows file activity as a sortable table and flags deletions', async () => {
    mockRecords('UsnJournalEntry', [
      rec('u1', {
        type: 'UsnJournalEntry',
        timestamp: '2026-08-01T10:00:00Z',
        file_name: 'secrets.docx',
        primary_operation: 'FILE_DELETE',
        reason_names: 'FILE_DELETE|CLOSE',
        usn: '123456',
        file_reference: '0x0004000000000123',
        parent_reference: '0x0004000000000005',
      }),
      rec('u2', {
        type: 'UsnJournalEntry',
        timestamp: '2026-08-01T09:00:00Z',
        file_name: 'notes.txt',
        primary_operation: 'DATA_EXTEND',
        reason_names: 'DATA_EXTEND',
        usn: '123400',
      }),
    ])
    renderViewer('UsnJournalEntry')

    expect((await screen.findAllByText('secrets.docx')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('notes.txt').length).toBeGreaterThan(0)
    // The USN is evidence and must be shown exactly, not rounded or reformatted.
    expect(screen.getByText('123456')).toBeInTheDocument()
    // Deletion is usually the only surviving record that a file existed.
    // The notable reason is surfaced as the flag badge's tooltip.
    await waitFor(() =>
      expect(screen.getByTitle(/file deleted/i)).toBeInTheDocument(),
    )
  })
})

describe('NtfsLogFileRecord viewer', () => {
  it('renders transaction records and discloses a payload spanning pages', async () => {
    mockRecords('NtfsLogFileRecord', [
      rec('l1', {
        type: 'NtfsLogFileRecord',
        record_number: 537,
        lsn: '0x000000000060bef6',
        operation: 'UpdateResidentValue',
        undo_operation_name: 'UpdateResidentValue',
        page_number: 95,
        transaction_id: 24,
        target_attribute: 24,
        multi_page: true,
      }),
    ])
    renderViewer('NtfsLogFileRecord')

    expect(await screen.findByText('0x000000000060bef6')).toBeInTheDocument()
    expect(screen.getAllByText('UpdateResidentValue').length).toBeGreaterThan(0)
    // A record decoded from its first page only must say so in the LISTING, not
    // only on its own page: an examiner scanning for an operation would
    // otherwise read a partial decode as a complete one.
    await waitFor(() =>
      expect(screen.getByTitle(/spans pages/i)).toBeInTheDocument(),
    )
  })
})

describe('browser artefact viewers', () => {
  it('shows cookies with their security flags spelled out', async () => {
    mockRecords('BrowserCookie', [
      rec('c1', {
        type: 'BrowserCookie',
        host: 'example.com',
        cookie_name: 'session',
        browser: 'Chrome/Edge',
        creation_time: 1767225600,
        is_secure: true,
        is_httponly: false,
      }),
    ])
    renderViewer('BrowserCookie')

    expect((await screen.findAllByText('example.com')).length).toBeGreaterThan(0)
    expect(screen.getByText('session')).toBeInTheDocument()
    // A boolean flag rendered as "true"/"false" tells an examiner nothing about
    // what it means; these are spelled.
    expect(screen.getByText('secure')).toBeInTheDocument()
    expect(screen.getByText('script-readable')).toBeInTheDocument()
  })

  it('reports whether a login had a stored password without revealing one', async () => {
    mockRecords('BrowserLogin', [
      rec('g1', {
        type: 'BrowserLogin',
        origin_url: 'https://mail.example.com/login',
        username: 'alice',
        has_saved_password: true,
        times_used: 12,
        browser: 'Chrome/Edge',
      }),
    ])
    renderViewer('BrowserLogin')

    expect((await screen.findAllByText('alice')).length).toBeGreaterThan(0)
    expect(screen.getByText('stored (encrypted)')).toBeInTheDocument()
    // The password itself is never decrypted into the listing.
    expect(screen.queryByText(/password:/i)).toBeNull()
  })

  it('shows autofill values and open tabs', async () => {
    mockRecords('BrowserAutofill', [
      rec('f1', {
        type: 'BrowserAutofill',
        field_name: 'email',
        value: 'alice@example.com',
        use_count: 4,
        browser: 'Chrome/Edge',
      }),
    ])
    renderViewer('BrowserAutofill')
    expect((await screen.findAllByText('email')).length).toBeGreaterThan(0)
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
  })
})

describe('YaraMatch viewer', () => {
  it('shows the rule that matched and the size of the set it came from', async () => {
    mockRecords('YaraMatch', [
      rec('y1', {
        type: 'YaraMatch',
        rule: 'Mimikatz_Strings',
        namespace: 'default',
        tags: 'credential_theft',
        rules_in_set: 412,
      }),
    ])
    renderViewer('YaraMatch')

    expect((await screen.findAllByText('Mimikatz_Strings')).length).toBeGreaterThan(0)
    // "N matched" with no denominator is a number with no scale: how many rules
    // were actually run is what makes a match, or an absence, mean anything.
    expect(screen.getByText('412')).toBeInTheDocument()
  })
})

describe('Linux login accounting viewers', () => {
  it('shows sessions with their source host and duration', async () => {
    mockRecords('LoginSession', [
      rec('s1', {
        type: 'LoginSession',
        user: 'root',
        tty: 'pts/0',
        host: '10.0.0.9',
        login_time: 1767225600,
        logout_time: 1767229200,
        duration_seconds: 3600,
        pid: 4242,
      }),
    ])
    renderViewer('LoginSession')

    expect((await screen.findAllByText('root')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('10.0.0.9').length).toBeGreaterThan(0)
    expect(screen.getByText('3,600')).toBeInTheDocument()
  })

  it('shows failed logins, which is where a brute-force burst becomes visible', async () => {
    mockRecords('FailedLogin', [
      rec('b1', {
        type: 'FailedLogin',
        user: 'admin',
        tty: 'ssh:notty',
        host: '203.0.113.7',
        // `time`, because that is the key the btmp producer writes
        // (seance_plugin_utmp, pinned by its own tests). This fixture said
        // `timestamp`, which is what the VIEWER read — so the two agreed with
        // each other and with no record the product has ever produced, and
        // the Time column was empty on every real screen while this passed.
        time: 1767225600,
        ut_type: 'LOGIN_PROCESS',
        pid: 9001,
      }),
    ])
    renderViewer('FailedLogin')

    expect((await screen.findAllByText('admin')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('203.0.113.7').length).toBeGreaterThan(0)
    // The time is rendered, from the producer's key.
    expect(screen.getAllByText(/2026-01-01/).length).toBeGreaterThan(0)
  })

  it('marks a boot record whose clock could not be trusted', async () => {
    mockRecords('BootEvent', [
      rec('t1', {
        type: 'BootEvent',
        kind: 'boot',
        ut_type: 'BOOT_TIME',
        record_index: 3,
        time_unusable: true,
      }),
    ])
    renderViewer('BootEvent')

    expect((await screen.findAllByText('boot')).length).toBeGreaterThan(0)
    // An unusable timestamp must be visible where the record is read; a boot
    // time is what other events get ordered against.
    await waitFor(() =>
      expect(screen.getByTitle(/timestamp not usable/i)).toBeInTheDocument(),
    )
  })

  it('shows lastlog by uid, leaving an absent user name absent', async () => {
    mockRecords('LastLogin', [
      rec('n1', {
        type: 'LastLogin',
        uid: 1000,
        user: null,
        tty: 'pts/1',
        host: '10.0.0.5',
        // The lastlog producer's key. See the FailedLogin fixture above.
        last_login_time: 1767225600,
      }),
    ])
    renderViewer('LastLogin')

    expect(await screen.findByText('1,000')).toBeInTheDocument()
    expect(screen.getAllByText(/2026-01-01/).length).toBeGreaterThan(0)
    // `lastlog` is indexed by uid and carries no name. The parser writes null
    // rather than inventing one, and the viewer must not invent one either.
    expect(screen.queryByText('null')).toBeNull()
    expect(screen.queryByText('undefined')).toBeNull()
  })
})

/**
 * macOS keeps no `btmp` and, since 10.5, no on-disk `wtmpx`: the login history
 * is in the OpenBSM audit trail. These are the two screens a macOS login
 * question is answered from.
 */
describe('macOS audit trail viewers', () => {
  it('shows an audit event with its outcome, the address it came from, and the binary that asked', async () => {
    mockRecords('AuditEvent', [
      rec('a1', {
        type: 'AuditEvent',
        event_id: 32800,
        event_name: 'AUE_openssh',
        event_class: 'lo',
        event_class_description: 'login/logout',
        outcome: 'failed',
        timestamp: 1767225600,
        audit_user_id: 501,
        pid: 1592,
        source_address: '184.171.155.71',
        signing_id: 'com.apple.sshd',
        message: 'invalid password for user eliflatt',
      }),
    ])
    renderViewer('AuditEvent')

    expect((await screen.findAllByText('AUE_openssh')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('184.171.155.71').length).toBeGreaterThan(0)
    expect(screen.getAllByText('com.apple.sshd').length).toBeGreaterThan(0)
    expect(
      screen.getAllByText('invalid password for user eliflatt').length,
    ).toBeGreaterThan(0)
    // A refusal must be visible without opening the row: whether the system
    // said no is the whole question. The reason is the flag badge's tooltip.
    await waitFor(() =>
      expect(screen.getByTitle(/refused this/i)).toBeInTheDocument(),
    )
    expect(screen.getAllByText(/2026-01-01/).length).toBeGreaterThan(0)
  })

  it('flags an Apple System Log entry that is login history, in a list that is mostly noise', async () => {
    mockRecords('AslMessage', [
      rec('a1', {
        type: 'AslMessage',
        timestamp: 1767225600,
        level: 5,
        level_name: 'notice',
        sender: 'sshd: eliflatt [priv]',
        facility: 'com.apple.system.lastlog',
        pid: 1598,
        message: 'USER_PROCESS: 1601 ttys001',
        host: 'stu-21-155-171-184',
      }),
      rec('a2', {
        type: 'AslMessage',
        timestamp: 1767225601,
        level: 5,
        level_name: 'notice',
        sender: 'com.apple.xpc.launchd',
        facility: 'user',
        pid: 1,
        message: 'Service exited',
      }),
    ])
    renderViewer('AslMessage')

    expect(
      (await screen.findAllByText('com.apple.system.lastlog')).length,
    ).toBeGreaterThan(0)
    expect(screen.getAllByText('sshd: eliflatt [priv]').length).toBeGreaterThan(0)
    // macOS keeps no wtmpx, so the one login record among the launchd noise
    // must be visible without opening it.
    await waitFor(() =>
      expect(
        screen.getByTitle(/login history: macOS keeps this nowhere else/i),
      ).toBeInTheDocument(),
    )
  })

  it('shows the MRU path read out of the shell item, one name per level', async () => {
    // HUNT-127: the name used to come from a scan for delimited printable
    // runs. It now comes from each item's own structure, and the path is an
    // array the generic flat table would have skipped entirely.
    mockRecords('ShellMruEntry', [
      rec('m1', {
        type: 'ShellMruEntry',
        mru_kind: 'RecentDocs',
        display_name: 'report.docx',
        shell_item_name: 'report.docx',
        shell_item_path: ['Users', 'bob', 'report.docx'],
        shell_item_parsed: false,
        mru_position: 0,
        extension: 'docx',
        key_path: 'NTUSER.DAT\\...\\RecentDocs\\.docx',
      }),
      rec('m2', {
        type: 'ShellMruEntry',
        mru_kind: 'RecentDocs',
        display_name: 'stale.docx',
        order_source: 'not_listed',
        key_path: 'NTUSER.DAT\\...\\RecentDocs\\.docx',
      }),
    ])
    renderViewer('ShellMruEntry')

    expect((await screen.findAllByText('report.docx')).length).toBeGreaterThan(0)
    // Every level of the path is on screen.
    expect(screen.getAllByText('Users').length).toBeGreaterThan(0)
    expect(screen.getAllByText('bob').length).toBeGreaterThan(0)
    // The row says part of the item is still unread.
    await waitFor(() =>
      expect(
        screen.getByTitle(/part of the shell item is unread/i),
      ).toBeInTheDocument(),
    )
    // And a stale entry with no position says that instead.
    expect(
      screen.getByTitle(/stale entry with no position/i),
    ).toBeInTheDocument()
  })

  it('shows when a folder was browsed and says the times carry no zone', async () => {
    // A shellbag's value is "this folder was browsed, and here is when". The
    // record carried no time at all until the BEEF0004 block was read, and a
    // column of RFC 3339 strings reads as UTC unless the row says otherwise —
    // these are local wall-clock as Explorer wrote them.
    mockRecords('ShellBagEntry', [
      rec('s1', {
        type: 'ShellBagEntry',
        path: 'ROOT:BagMRU\\Desktop\\Quarterly',
        folder_name: 'Quarterly',
        slot: '0',
        folder_modified: '2021-06-15T14:30:44+00:00',
        folder_created: '2019-01-02T03:04:06+00:00',
        folder_accessed: '2021-12-31T23:59:58+00:00',
        timezone: 'local',
      }),
      rec('s2', {
        type: 'ShellBagEntry',
        path: 'ROOT:BagMRU',
        folder_name: 'This PC',
        slot: '0',
      }),
    ])
    renderViewer('ShellBagEntry')

    expect((await screen.findAllByText('Quarterly')).length).toBeGreaterThan(0)
    await waitFor(() =>
      expect(
        screen.getByTitle(/local wall-clock as Explorer wrote them/i),
      ).toBeInTheDocument(),
    )
    // The GUID-folder entry beside it has no time, so it makes no zone claim
    // and is not flagged.
    expect(
      screen.getAllByTitle(/local wall-clock as Explorer wrote them/i),
    ).toHaveLength(1)
  })

  it('shows a shortcut to removable media as such, with the caution on the row', async () => {
    // The shortcut records the drive type and the reader used to discard it.
    // "Removable" is the question this record class is most often asked, and
    // it is also the easiest to over-read: it is what Windows thought when
    // the shortcut was written.
    mockRecords('LnkFile', [
      rec('l1', {
        type: 'LnkFile',
        target_local_path: 'E:\\photos\\DSC001.jpg',
        drive_type: 2,
        drive_type_name: 'removable',
        volume_serial: 'A1B2-C3D4',
        volume_label: 'EVIDENCE',
        target_size_recorded: 204800,
      }),
      rec('l2', {
        type: 'LnkFile',
        target_local_path: 'C:\\Users\\bob\\report.docx',
        drive_type: 3,
        drive_type_name: 'fixed',
        volume_serial: 'DEAD-BEEF',
      }),
    ])
    renderViewer('LnkFile')

    expect((await screen.findAllByText('EVIDENCE')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('A1B2-C3D4').length).toBeGreaterThan(0)
    await waitFor(() =>
      expect(
        screen.getByTitle(/lead towards external media, not proof/i),
      ).toBeInTheDocument(),
    )
    // And the fixed-disk shortcut beside it is not flagged.
    expect(
      screen.getAllByTitle(/lead towards external media, not proof/i),
    ).toHaveLength(1)
  })

  it('shows the LinkTargetIDList path read out of the shell item, one name per level', async () => {
    // ROADMAP §5.16: LinkTargetIDList used to be read only far enough to
    // step past. It is now walked through the format, same as the MRU
    // reader's shell item -- and this column was missing from the viewer
    // even after the backend shipped it.
    mockRecords('LnkFile', [
      rec('l3', {
        type: 'LnkFile',
        target_local_path: 'C:\\Users\\bob\\report.docx',
        shell_item_name: 'report.docx',
        shell_item_path: ['Users', 'bob', 'report.docx'],
        shell_item_modified: '2024-01-01T00:00:00Z',
      }),
    ])
    renderViewer('LnkFile')

    expect((await screen.findAllByText('report.docx')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('Users').length).toBeGreaterThan(0)
    expect(screen.getAllByText('bob').length).toBeGreaterThan(0)
  })

  it('says on every row that a logging catalogue is not a record that the binary ran', async () => {
    mockRecords('UnifiedLogImage', [
      rec('u1', {
        type: 'UnifiedLogImage',
        image_path: '/usr/sbin/bluetoothd',
        image_uuid: '51A230C8287F307CA652F723CC388382',
        image_uuid_source: "this file's own name",
        format_strings: 412,
        source_file: '51/A230C8287F307CA652F723CC388382',
      }),
      rec('u2', {
        type: 'UnifiedLogImage',
        image_path: '/usr/lib/system/libxpc.dylib',
        image_uuid_recorded: false,
        format_strings: 800,
        source_file: 'carved_000123.bin',
      }),
    ])
    renderViewer('UnifiedLogImage')

    expect(
      (await screen.findAllByText('/usr/sbin/bluetoothd')).length,
    ).toBeGreaterThan(0)
    await waitFor(() =>
      expect(
        screen.getByTitle(/not a record that it ran/i),
      ).toBeInTheDocument(),
    )
    // And a file whose name was not preserved says it cannot be matched to a
    // log reference, rather than showing an empty UUID column.
    expect(
      screen.getByTitle(/cannot be matched to a log reference/i),
    ).toBeInTheDocument()
  })

  it('says on the row when a unified-log message was not resolved and shows no text for it', async () => {
    mockRecords('UnifiedLogMessage', [
      rec('m1', {
        type: 'UnifiedLogMessage',
        timestamp: 1642303933,
        activity_type: 'log',
        level: 'Default',
        process: '/usr/libexec/opendirectoryd',
        pid: 105,
        subsystem: 'com.apple.opendirectoryd',
        message: 'opendirectoryd (build 796.100) launched...',
        resolved: true,
        time_source: 'timesync',
        dated: true,
      }),
      rec('m2', {
        type: 'UnifiedLogMessage',
        timestamp: 1642303934,
        activity_type: 'log',
        resolved: false,
        unresolved_reason: 'offset 0x422304 outside its entry ranges',
        time_source: 'timesync',
        dated: true,
      }),
    ])
    renderViewer('UnifiedLogMessage')

    expect(
      (await screen.findAllByText('opendirectoryd (build 796.100) launched...')).length,
    ).toBeGreaterThan(0)
    await waitFor(() =>
      expect(screen.getByTitle(/not resolved: offset 0x422304/i)).toBeInTheDocument(),
    )
  })

  it('shows an indexed file with its path, sizes and dates', async () => {
    mockRecords('SpotlightItem', [
      rec('i1', {
        type: 'SpotlightItem',
        item_id: 144992,
        path: '/Applications/checkra1n.app',
        path_complete: true,
        file_name: 'checkra1n.app',
        content_type: 'com.apple.application-bundle',
        logical_size: 10517116,
        use_count: 6,
        uid: 501,
        last_used: '2021-02-22T04:06:32.022643+00:00',
        indexed_at: '2021-03-28T06:34:40.414471+00:00',
        source_file: 'store.db',
      }),
    ])
    renderViewer('SpotlightItem')

    expect(
      (await screen.findAllByText('/Applications/checkra1n.app')).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getAllByText('com.apple.application-bundle').length,
    ).toBeGreaterThan(0)
  })

  it('says on the row when a Spotlight path is not an absolute one', async () => {
    // A volume's index is split across stores, so a parent chain can leave
    // the file being read. Rendering the segments below that point with a
    // leading slash would state a location the evidence does not support, and
    // the caution has to be where the value is read off.
    mockRecords('SpotlightItem', [
      rec('i2', {
        type: 'SpotlightItem',
        item_id: 200,
        path: 'orphan.txt',
        path_complete: false,
        file_name: 'orphan.txt',
        source_file: 'store.db',
      }),
      rec('i3', {
        type: 'SpotlightItem',
        item_id: 201,
        path: '/Users/stops-here.txt',
        path_complete: true,
        attributes_complete: false,
        file_name: 'stops-here.txt',
        source_file: 'store.db',
      }),
    ])
    renderViewer('SpotlightItem')

    await waitFor(() =>
      expect(
        screen.getByTitle(/parent chain leaves this store/i),
      ).toBeInTheDocument(),
    )
    // And an item whose attribute stream stopped part way says that too,
    // rather than looking like a file with little metadata.
    expect(
      screen.getByTitle(/part of this item's metadata was not decoded/i),
    ).toBeInTheDocument()
  })

  it('shows the Spotlight attributes a volume indexed, with the store each came from', async () => {
    mockRecords('SpotlightProperty', [
      rec('p1', {
        type: 'SpotlightProperty',
        property_id: 74,
        attribute: 'kMDItemContentTypeTree',
        property_type: 15,
        value_type: 74,
        source_file: 'store.db',
      }),
      rec('p2', {
        type: 'SpotlightProperty',
        property_id: 11,
        attribute: 'kMDItemWhereFroms',
        property_type: 11,
        value_type: 66,
        source_file: 'store.db',
      }),
    ])
    renderViewer('SpotlightProperty')

    expect(
      (await screen.findAllByText('kMDItemContentTypeTree')).length,
    ).toBeGreaterThan(0)
    // The attribute that says where a download came from, which is why this
    // table is read at all.
    expect(screen.getAllByText('kMDItemWhereFroms').length).toBeGreaterThan(0)
  })

  it('warns on every content-type row that the index knowing a type is not a file being there', async () => {
    mockRecords('SpotlightContentType', [
      rec('c1', {
        type: 'SpotlightContentType',
        category_id: 12,
        content_type: 'com.apple.mail.emlx',
        source_file: 'store.db',
      }),
      rec('c2', {
        type: 'SpotlightContentType',
        category_id: 44,
        content_type: 'com.apple.ichat.transcript',
        source_file: 'store.db',
      }),
    ])
    renderViewer('SpotlightContentType')

    expect(
      (await screen.findAllByText('com.apple.mail.emlx')).length,
    ).toBeGreaterThan(0)
    // The whole reason this type has a tailored viewer: the per-item records
    // are not decodable, so a content type is what the index knew about and
    // may be there because of a file since deleted. Read off a row, not off a
    // paragraph at the top that a screenshot loses.
    await waitFor(() =>
      expect(
        screen.getAllByTitle(/a matching file need not exist now/i).length,
      ).toBeGreaterThan(1),
    )
  })

  it('shows an iCloud keychain device and flags a zone that was not syncing', async () => {
    mockRecords('ICloudKeychainDevice', [
      rec('d1', {
        type: 'ICloudKeychainDevice',
        cloudkit_zone: 'Manatee',
        os_version: 'macOS 20.3.0 (20D74)',
        sos_circle_status: 'kSOSCCInCircle',
        octagon_peer_id: 'SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=',
        octagon_status: 'CliqueStatusIn',
        key_state: 'ready',
      }),
      rec('d2', {
        type: 'ICloudKeychainDevice',
        cloudkit_zone: 'ApplePay',
        os_version: 'watch 19.6.0 (17U63)',
        sos_circle_status: 'kSOSCCError',
        octagon_status: 'CliqueStatusIn',
      }),
    ])
    renderViewer('ICloudKeychainDevice')

    expect(
      (await screen.findAllByText('macOS 20.3.0 (20D74)')).length,
    ).toBeGreaterThan(0)
    expect(screen.getAllByText('watch 19.6.0 (17U63)').length).toBeGreaterThan(0)
    expect(
      screen.getAllByText(
        'SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=',
      ).length,
    ).toBeGreaterThan(0)
    // The circle status is per zone, so a zone in error must be visible on the
    // row rather than only inside it.
    await waitFor(() =>
      expect(screen.getByTitle(/this zone was not syncing/i)).toBeInTheDocument(),
    )
  })

  it('shows a keychain item and marks its secret locked on the row', async () => {
    mockRecords('KeychainItem', [
      rec('k1', {
        type: 'KeychainItem',
        item_kind: 'generic_password',
        PrintName: 'e.flatt610@gmail.com',
        service: 'iCloud',
        account: '20118734345',
        // The keychain's dates are ISO-like strings, not epoch integers.
        created: '20210212003531Z',
        modified: '20210405223108Z',
        secret_state: 'locked',
        secret_wrapping: 'ssgp_master_key',
      }),
    ])
    renderViewer('KeychainItem')

    expect(
      (await screen.findAllByText('e.flatt610@gmail.com')).length,
    ).toBeGreaterThan(0)
    expect(screen.getAllByText('iCloud').length).toBeGreaterThan(0)
    expect(screen.getAllByText('20118734345').length).toBeGreaterThan(0)
    expect(screen.getAllByText('20210212003531Z').length).toBeGreaterThan(0)
    // An examiner must never read a keychain item as a credential that was
    // recovered. The reason is the flag badge's tooltip.
    await waitFor(() =>
      expect(
        screen.getByTitle(/secret is encrypted and was not recovered/i),
      ).toBeInTheDocument(),
    )
    expect(screen.queryByText('undefined')).toBeNull()
  })

  it('IosKeychainItem viewer marks withheld and device-bound secrets and never renders v_Data', async () => {
    mockRecords('IosKeychainItem', [
      rec('ik1', {
        type: 'IosKeychainItem',
        table: 'genp',
        item_kind: 'generic_password',
        state: 'read',
        service: 'AirPort',
        account: 'HomeNetwork',
        access_group: 'apple',
        keychain_class_name: 'AfterFirstUnlock',
        created: '2023-07-01T20:16:21.637078Z',
        secret_present: true,
        secret_state: 'withheld',
        // The backend never emits this; the screen must not show it even if
        // it arrived.
        v_Data: 'SUPERSECRETVALUE',
      }),
      rec('ik2', {
        type: 'IosKeychainItem',
        table: 'genp',
        item_kind: 'generic_password',
        state: 'device_bound',
        keychain_class_name: 'AfterFirstUnlockThisDeviceOnly',
        secret_state: 'locked',
        secret_present: null,
      }),
    ])
    renderViewer('IosKeychainItem')

    expect((await screen.findAllByText('HomeNetwork')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('AirPort').length).toBeGreaterThan(0)
    await waitFor(() =>
      expect(
        screen.getByTitle(/decrypted but is withheld/i),
      ).toBeInTheDocument(),
    )
    expect(
      screen.getByTitle(/bound to the device.*a backup does not carry/i),
    ).toBeInTheDocument()
    expect(screen.queryByText(/SUPERSECRETVALUE/)).toBeNull()
    expect(screen.queryByText('undefined')).toBeNull()
  })

  it('shows the numeric account on a failed login, because the audit trail carries no name', async () => {
    mockRecords('FailedLogin', [
      rec('f1', {
        type: 'FailedLogin',
        // No `user`: the trail names the account by number, and a name parsed
        // out of the daemon's prose would be a guess. An empty User column
        // would read as no attacker rather than as a numeric identity.
        user_id: 501,
        time: 1767225600,
        ip: '184.171.155.71',
        event_name: 'AUE_openssh',
        ut_type: 'AUE_openssh',
        source_file: 'audit_trail',
        pid: 1592,
        message: 'invalid password for user eliflatt',
      }),
    ])
    renderViewer('FailedLogin')

    expect((await screen.findAllByText('501')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('184.171.155.71').length).toBeGreaterThan(0)
    expect(screen.getAllByText('audit_trail').length).toBeGreaterThan(0)
    expect(screen.queryByText('undefined')).toBeNull()
  })
})
