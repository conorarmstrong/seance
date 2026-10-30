import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { NAV_SECTIONS } from '../../app/nav'
import { HelpPage } from './HelpPage'

/**
 * The rendered text of one section, whitespace-collapsed.
 *
 * The keyboard documentation is dense with <strong>, <span className="help-kbd">
 * and <code>, so almost every sentence in it is split across half a dozen text
 * nodes. Matching on the section's own textContent asserts what an examiner
 * READS, which is the only thing that matters for a page whose whole job is to
 * be checkable against the product.
 */
function sectionText(container: HTMLElement, id: string): string {
  const section = container.querySelector(`#${id}`)
  if (!section) throw new Error(`no help section #${id}`)
  const clone = section.cloneNode(true) as HTMLElement
  // Figures are dropped: the nav diagram is DERIVED from NAV_SECTIONS, so its
  // labels are there by construction and would answer "is every rail item
  // documented?" with the question restated. What these assertions are for is
  // the PROSE, which is hand-written and is therefore the half that drifts.
  for (const figure of clone.querySelectorAll('figure')) figure.remove()
  return (clone.textContent ?? '').replace(/\s+/g, ' ')
}

const SECTIONS: [string, string][] = [
  ['getting-started', 'Getting started'],
  ['navigation', 'Navigating a case'],
  ['ingestion', 'Evidence ingestion'],
  ['users', 'Users and access control'],
  ['dashboard', 'Dashboard and case overview'],
  ['timeline', 'Timeline analysis'],
  ['search', 'Search'],
  ['file-browser', 'File browser'],
  ['carving', 'File carving and recovery'],
  ['artifacts', 'Artifact parsers'],
  ['analysis-records', 'Records analysis'],
  ['entities', 'Entities and link analysis'],
  ['media-geo', 'Gallery and geolocation'],
  ['review-ledger', 'Review ledger: opened and reviewed'],
  ['bookmarks', 'Bookmarks'],
  ['hash-sets', 'Hash sets'],
  ['reporting', 'Reporting and exports'],
  ['filesystems', 'Filesystems and containers'],
  ['encryption', 'Encrypted volumes'],
  ['integrity', 'Integrity and audit'],
  ['soundness', 'Forensic soundness'],
  ['shortcuts', 'Keyboard shortcuts'],
  ['tips', 'Tips and good practice'],
]

function renderHelp() {
  return render(
    <MemoryRouter>
      <HelpPage />
    </MemoryRouter>,
  )
}

describe('HelpPage', () => {
  it('renders every documentation section with a heading and matching id', () => {
    renderHelp()
    for (const [id, title] of SECTIONS) {
      const heading = screen.getByRole('heading', { name: title })
      expect(heading.closest('section')).toHaveAttribute('id', id)
    }
  })

  it('documents nested bookmark folders and what deleting one does (§3.15)', () => {
    // BookmarksPage's New category "Parent folder" and the server's rules: same
    // case, no cycle, bounded depth, subfolders promoted on delete, and the report
    // naming the folder by its whole path.
    const { container } = renderHelp()
    const text = sectionText(container, 'bookmarks')
    expect(text).toMatch(/Parent folder/)
    expect(text).toMatch(/five levels/i)
    expect(text).toMatch(/subfolders[^.]*top level/i)
    expect(text).toMatch(/report name a bookmark.s folder by its whole path/i)
  })

  it('documents due dates, the derived overdue flag and reassignment (§3.15)', () => {
    // AssignPanel's Due field, AssignmentsOverview's Reassign / Withdraw, and the
    // server's is_overdue: overdue is derived from the ledger, never stored, and a
    // reassignment keeps the earlier assignment on the record.
    const { container } = renderHelp()
    const text = sectionText(container, 'review-ledger')
    expect(text).toMatch(/due date/i)
    expect(text).toMatch(/Overdue/)
    expect(text).toMatch(/never stored|not stored/i)
    expect(text).toMatch(/Reassign/)
    expect(text).toMatch(/earlier assignment[^.]*kept/i)
  })

  it('documents assignment, its read_only refusal, and personal bookmarks (§3.15)', () => {
    const { container } = renderHelp()
    const ledger = container.querySelector('section#review-ledger')!
    expect(ledger).toHaveTextContent('Assigned work')
    expect(ledger).toHaveTextContent('read_only')
    expect(ledger).toHaveTextContent(/counts only the assignee.s own reviews/)
    const bookmarks = container.querySelector('section#bookmarks')!
    expect(bookmarks).toHaveTextContent('Mark privately')
    expect(bookmarks).toHaveTextContent(/never included in a report/)
    expect(bookmarks).toHaveTextContent(/states how many/)
  })

  it('documents key examiner workflows', () => {
    renderHelp()
    expect(screen.getAllByText(/E01/).length).toBeGreaterThan(0)
    expect(screen.getByText(/\+required/)).toBeInTheDocument()
    expect(screen.getAllByText(/NSRL/).length).toBeGreaterThan(0)
  })

  it('documents the byte sweep panel and /sweep, and no longer calls it API-only (§1.2)', () => {
    const { container } = renderHelp()
    const text = sectionText(container, 'search')
    expect(text).not.toMatch(/has no screen yet/)
    expect(text).toMatch(/Byte sweep of the evidence bytes/)
    expect(text).toMatch(/\/sweep/)
    expect(text).toMatch(/Incomplete/)
    expect(text).toMatch(/Resume from where this sweep stopped/)
    expect(text).toMatch(/both UTF-16 byte orders/)
    expect(text).toMatch(/slack/i)
  })

  it('describes BitLocker as decryptable, not merely detected', () => {
    // Regression: BitLocker support moved from detection-only to full
    // decryption (AES-XTS / AES-CBC+diffuser); the encryption table must not
    // claim the old "detect only" behavior for it.
    renderHelp()
    expect(
      screen.getByText(/Decrypt with password or recovery key/),
    ).toBeInTheDocument()
    expect(screen.getByText(/AES-XTS 128\/256/)).toBeInTheDocument()
  })

  it('does not claim the hibernation header reaches the timeline', () => {
    // Regression: the memory-analysis copy said the hibernation write time
    // "reaches the timeline". No memory crate emits a TimelineEvent artifact —
    // the fact reaches the capture profile page and nowhere else — so an
    // examiner who searched the timeline for it would find nothing and read
    // that as the machine never having hibernated.
    renderHelp()
    expect(screen.queryByText(/reaches the timeline/)).not.toBeInTheDocument()
    expect(
      screen.getByText(/they are not\s+timeline events/),
    ).toBeInTheDocument()
  })

  it('says macOS captures are analysed, and that the tier is unvalidated', () => {
    // Regression, in both directions. The help said "macOS captures are not
    // analysed", which stopped being true when the tier was registered, and
    // promised a macOS image would be "said to be unsupported", which was never
    // true — nothing anywhere emitted that status, so a Mac capture produced
    // silence while the help described a message. What must survive every
    // rewrite is the warning itself: this analysis has never been run against a
    // real Mac capture, and the help is where an examiner learns that before
    // they quote a process list from it.
    renderHelp()
    expect(
      screen.getByText(/is covered by four stages and a warning/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        /Nothing the macOS analysis produces has ever been checked/,
      ),
    ).toBeInTheDocument()
    expect(screen.queryByText(/said to be unsupported/)).toBeNull()
    expect(screen.queryByText(/macOS captures are not analysed/)).toBeNull()
  })

  it('states that swapped pages are resolvable on both Windows and Linux', () => {
    // The help must tell an examiner that a swapped-out page is recoverable on
    // either OS by attaching the pagefile/swap area — a hole they do not know
    // is recoverable is one they read as an absence.
    renderHelp()
    expect(screen.getByText('SEANCE_PAGEFILES')).toBeInTheDocument()
    expect(screen.getByText('SEANCE_SWAPFILES')).toBeInTheDocument()
    expect(
      screen.getByText(/Swapped-out pages are recoverable on Windows and Linux/),
    ).toBeInTheDocument()
  })

  it('warns, before acquisition, that a swap file copied through the filesystem reads back as zeros', () => {
    // The hazard this documents is silent and total: `cp /swapfile` yields a
    // copy whose body is zeros, because the swapped pages sit in fallocate'd
    // extents ext4 still records as unwritten, while the mkswap-written header
    // page copies perfectly — so the copy parses as swap, attaches and
    // corroborates entries, and passes every inspection an examiner makes.
    // Séance detects it and refuses to call such a page recovered, but that
    // finding reaches the profile record, and the only person who can still
    // fix it is the one standing at the machine before it is gone. So the
    // hazard, the tell and the remedy have to be here, where they are read
    // ahead of acquisition rather than after it.
    renderHelp()
    expect(
      screen.getByRole('heading', { name: 'Acquiring a Linux swap area' }),
    ).toBeInTheDocument()
    // The mechanism, the tell, and the measurement behind the claim.
    expect(screen.getByText(/records the extents as/)).toBeInTheDocument()
    expect(screen.getByText(/passes inspection/)).toBeInTheDocument()
    expect(screen.getByText(/724,505/)).toBeInTheDocument()
    // The remedy, named exactly as an operator would type it.
    expect(screen.getByText('filefrag -v /swapfile')).toBeInTheDocument()
    // ...and the limit the code refuses to overstate: zeros are an
    // observation, and three different histories produce them.
    expect(
      screen.getByText(/cannot tell the three apart/),
    ).toBeInTheDocument()
  })

  it('says why an undeclared memory capture produces nothing, and how to declare it', () => {
    // Regression (MEM-014): a headerless capture (.mem/.vmem/.ram) ingested
    // without a declaration is accepted as ordinary evidence and yields no
    // memory record, no warning and no processing-log row — output identical to
    // a case that never had a capture in it. The examiner's usual conclusion is
    // "Séance cannot do memory", when the missing piece is one declaration. The
    // help is where that symptom gets looked up, so it has to carry the symptom
    // AND both ways of making the declaration; before this it carried a single
    // clause about declaring at ingest and nothing an examiner could search for.
    renderHelp()
    expect(
      screen.getByRole('heading', { name: 'A capture that produced nothing' }),
    ).toBeInTheDocument()
    // The refuse-to-guess reason, so the silence reads as a decision.
    expect(screen.getByText(/a name is not evidence/)).toBeInTheDocument()
    // The UI control, named exactly as it appears in the ingest dialog.
    expect(
      screen.getByText(
        /I declare this source to be a capture of physical memory/,
      ),
    ).toBeInTheDocument()
    // ...and the command-line and metadata equivalents.
    expect(screen.getByText('--memory-image')).toBeInTheDocument()
    expect(screen.getByText('memory_image_format')).toBeInTheDocument()
  })

  it('says network captures are read by content, reported as flows, and never resolved by the examination host', () => {
    // The pcap module shipped for a case whose capture was named `.pcap` and
    // was pcapng, so the help has to say detection is by content or an
    // examiner will rename the file and wait. It reports FLOWS, not packets,
    // and the only names it attaches to an address are DNS answers that were
    // themselves in the capture — an examiner reading a hostname beside a C2
    // address must know it came from the evidence, not from a lookup this
    // machine made today.
    const { container } = renderHelp()
    const text = sectionText(container, 'artifacts')
    expect(text).toMatch(/pcapng/)
    expect(text).toMatch(/named \.pcap/)
    expect(text).toMatch(/one record per conversation/)
    expect(text).toMatch(/othing is looked up from the examination host/)
    expect(text).toMatch(/no geolocation/)
  })

  it('says what the reassembled streams give, and what TLS and ARP do not', () => {
    // Stage 2 of the network tier reads the CONTENTS of a conversation, and
    // every claim here is one an examiner may quote: that a gap is never
    // closed, that a body is handed on as its own artifact, that a pairing
    // carries its basis, that TLS 1.3 encrypts the certificate so its absence
    // says nothing about the server, and that an ARP binding is a claim rather
    // than a fact. The last two are the ones a report would otherwise
    // overstate.
    const { container } = renderHelp()
    const text = sectionText(container, 'artifacts')
    expect(text).toMatch(/HttpTransaction/)
    expect(text).toMatch(/decoded form fields/)
    expect(text).toMatch(/on any port/)
    expect(text).toMatch(/its own file artifact/)
    expect(text).toMatch(/pairing may be wrong/)
    expect(text).toMatch(/JA3/)
    expect(text).toMatch(/From TLS 1.3 the certificate is encrypted/)
    expect(text).toMatch(/No signature is verified/)
    expect(text).toMatch(/ArpBinding/)
    expect(text).toMatch(/ARP does not authenticate/)
    expect(text).toMatch(/reaches no verdict/)
  })

  it('says a wireless profile states configuration, not a join, and where the key is', () => {
    // The two things a Windows WLAN profile does NOT say are the ones an
    // examiner will otherwise assume: when the machine joined, and what the
    // passphrase was when it is DPAPI-protected. Both are in the help because
    // both are in the record.
    const { container } = renderHelp()
    const text = sectionText(container, 'artifacts')
    expect(text).toMatch(/Windows wireless profiles/)
    expect(text).toMatch(/Wlansvc/)
    expect(text).toMatch(/when the machine joined, or that it ever did/)
    expect(text).toMatch(/this build does not decrypt it/)
    expect(text).toMatch(/WLAN-AutoConfig/)
  })

  describe('keyboard shortcuts', () => {
    // These are documentation OF BEHAVIOUR, so each one names a key that was
    // read out of the implementation before it was written down. The whole
    // value of this page is that an examiner can trust it without trying the
    // key first; a documented key that does nothing costs more than an
    // undocumented one that works.

    it('no longer confines the arrow keys to two tables', () => {
      // The old copy said the arrows moved "the selected row in the timeline
      // and file-browser tables". Five tables answer to them now, so that
      // sentence understated the product by three whole surfaces -- and an
      // examiner who reads that the audit log is not keyboard-navigable does
      // not try it.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).not.toMatch(/timeline and file-browser tables/)
    })

    it('names every table the arrow keys work in', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      for (const table of [
        'Timeline',
        'Audit log',
        'Search results',
        'Parsed records',
        'File browser',
      ]) {
        expect(text, `${table} missing from the tables shortcut list`).toContain(
          table,
        )
      }
      // ...and says that the whole table is one Tab stop, which is the fact
      // that makes a 500-row page usable at all.
      expect(text).toMatch(/one Tab stop for the whole table/i)
    })

    it('separates what Enter does per table rather than flattening it', () => {
      // Enter expands in the timeline and the audit log, and opens the artifact
      // in search, records and the file grid. One sentence covering all five
      // would be wrong for at least two of them.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/Timeline — expands/)
      expect(text).toMatch(/Audit log — expands/)
      expect(text).toMatch(/Search results — opens/)
      expect(text).toMatch(/Parsed records — opens/)
      expect(text).toMatch(/File browser — opens/)
    })

    it('documents the timeline row keys, including the one that is conditional', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/Space.{0,80}select/i)
      // `n` opens the note editor only on an event that is already tagged --
      // documenting it unconditionally would send an examiner pressing a key
      // that correctly does nothing.
      expect(text).toMatch(/only on an event you have already tagged/i)
    })

    it('documents the tree contract, and says which trees implement it', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toContain('Physical')
      expect(text).toContain('Logical')
      expect(text).toMatch(/Tree view/)
      // Right opens and then steps in on a SECOND press: one press that did
      // both would lose the examiner their place.
      expect(text).toMatch(/press it again to step inside/i)
      expect(text).toMatch(/closes an open row.{0,140}parent/i)
      // Type-ahead accumulates within a window and refuses to move on no match.
      expect(text).toMatch(/nothing matches what you have typed, nothing moves/i)
      // And it searches the rows on screen: `typeAhead` walks the rendered
      // `treeitem`s, so a name inside a collapsed branch or an unfetched level
      // is not a candidate. Left unsaid, "nothing matched" reads as "this case
      // holds no such folder".
      expect(text).toMatch(/searches only the rows the tree is showing/i)
    })

    it('says where Space differs between the trees', () => {
      // In the navigator trees Space activates the row's label; in the file
      // browser's tree it loads the file into the detail pane without leaving
      // the tree, which is a different thing and the reason the two are not
      // described in one sentence.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/detail pane without leaving the tree/i)
    })

    it('does not claim arrow keys on the disk map, which has none', () => {
      // The maps sat in a table captioned "Tables and maps" whose first row was
      // about arrow keys. The cells are individual Tab stops and answer to
      // Enter and Space only, so the page now says so rather than leaving the
      // arrows implied.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/no arrow-key navigation/i)
    })

    it('documents the row-copy key, and names the one table that has a copy column', () => {
      // `c` on a focused row copies that row's copy-column value. `RecordTable`
      // offers the column to any table that asks for it, and exactly one asks
      // today: the geotagged-photograph (EXIF) records view, where the value is
      // the coordinates. Documenting it as a key of "data tables" would have an
      // examiner press it on the timeline and conclude the product is broken.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/copy column/i)
      expect(text).toMatch(/latitude, longitude/i)
      // A row whose value is absent — a photograph carrying no GPS — has no
      // copy button and the key does nothing on it.
      expect(text).toMatch(/nothing to copy/i)
      // Modified presses are passed straight through, so the browser's own copy
      // of a selection keeps working.
      expect(text).toMatch(/Ctrl-C/)
    })

    it('says the gallery End key reaches the last LOADED item, not the last of the set', () => {
      // The gallery is server-paged behind an infinite scroll, so `End` moves to
      // `items.length - 1` — the end of what has been fetched. On a case of
      // 4,000 images with 200 loaded that is the 200th, and an examiner told
      // "jump to the last image" would read the 200th as the last one in the
      // case: a false absence built out of a keyboard shortcut.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/first or the last loaded/i)
      expect(text).toMatch(/not the end of the set/i)
      // And it points at the toolbar figure that says how far "loaded" reaches.
      expect(text).toMatch(/loaded.{0,40}whenever the two differ/i)
    })

    it('separates the gallery keys that need a highlight from the one that makes one', () => {
      // Space with nothing highlighted highlights the first item and opens
      // nothing; Enter with nothing highlighted does nothing at all. One
      // sentence covering both would be wrong for one of them.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/nothing highlighted yet it highlights the first item/i)
      expect(text).toMatch(/Unlike Space/)
    })

    it('says an item with no artifact behind it opens nothing', () => {
      // A chat-media attachment whose file is not in evidence has
      // `artifactId: null`; the cell says "not in evidence", and Space, Enter
      // and b are all gated on that id. Documented once for the three of them,
      // because a key that correctly does nothing reads as a broken product.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/not in evidence/i)
    })

    it('says the keys address the set a table holds, not the rows drawn', () => {
      // `VirtualRows` and `VirtualCells` render only the rows near the
      // viewport, and both pin the row the keyboard is on so it is rendered
      // wherever the scroll is (`pinnedIndex`). The windowing is therefore a
      // drawing decision and not a limit on reach, and the help has to say so:
      // an examiner who believes End stops at the bottom of what is drawn will
      // not press it.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/only the rows near the/i)
      expect(text).toMatch(/keys address the whole set the table is holding/i)
    })

    it('does not tell the parsed-records table that it is paged', () => {
      // Timeline, audit log, search results and the file grid are paged, so
      // End there is the end of the page. The records viewer is NOT paged: it
      // loads instalments into one growing table (`useRecordPages` +
      // "Load more"), so End is the last row LOADED. One sentence covering
      // both was wrong for one of them, in the same way "jump to the last
      // image" was wrong for the gallery.
      const { container } = renderHelp()
      const text = sectionText(container, 'shortcuts')
      expect(text).toMatch(/Parsed records.{0,120}last row loaded so far/i)
      expect(text).toMatch(/grows as you scroll or press Load more/i)
    })
  })

  describe('search — how deep the results and the export reach', () => {
    it('says jumping is what stops, and names the control that carries on', () => {
      // `max_offset` bounds a JUMP. `next_cursor` resumes where the last page
      // stopped, so Next walks past it. Conflating the two would tell an
      // examiner that matches they can count are matches they cannot read.
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).toMatch(/jumping/i)
      expect(text).toMatch(/Next keeps walking/i)
      // And what a walk costs: no page number, no Prev, but the browser's Back
      // still replays the pages actually read (`goToPage` pushes history).
      expect(text).toMatch(/no page number/i)
      expect(text).toMatch(/Back/)
    })

    it('says a walked position opened later is refused, not answered from a re-ordered index', () => {
      // The server refuses a cursor minted against a different index snapshot
      // (409 SEARCH_CURSOR_REFUSED) and the page renders that refusal rather
      // than a page of rows that look like a continuation.
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).toMatch(/refused/i)
      expect(text).toMatch(/start again|first page/i)
    })

    it('does not claim the export stops at a row count or a ceiling of its own', () => {
      // It used to take one capped page of 100,000 hits. It now walks the
      // whole match set by cursor and writes `row_limit,none` into the file.
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).not.toMatch(/export.{0,120}ceiling of its own/i)
      expect(text).toMatch(/walks the whole match set/i)
      // And it exports the match set rather than the page on screen: the page
      // deliberately strips `offset` and `cursor` from the export request.
      expect(text).toMatch(/whichever page you are on/i)
    })

    it('names the verdict row and says a file without it is a fragment', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).toContain('### END OF EXPORT ### VERDICT:')
      expect(text).toMatch(/including a complete one/i)
      expect(text).toMatch(/fragment/i)
      // The SHAPE of the row is the test, not the marker: the CSV row is
      // always quoted, and the marker in the preamble's own note is not it
      // (CR-025, CR-033 #4). The help must state the test a reader can apply.
      expect(text).toMatch(/always quoted/)
      expect(text).toMatch(/reading note is not that row/)
      expect(text).toMatch(/completeness/)
      // The three verdicts the server can write.
      expect(text).toMatch(/COMPLETE, STATED TOTAL WAS A FLOOR/)
      expect(text).toMatch(/INCOMPLETE/)
    })

    it('says a fragment on disk is kept exactly as it arrived', () => {
      // `streamToFile` closes rather than aborts the writable, and appends
      // nothing: what arrived is evidence, and a client that edited it would
      // make the file something other than what the server sent.
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).toMatch(/nothing appended|nothing is appended/i)
    })

    it('documents the display-name repair, and what it cannot do', () => {
      // The control is offered only to an examiner the server would let run
      // one, and the paragraph beside it exists to keep "reindexed" out of a
      // report as a claim about coverage: the pass walks what is already
      // indexed and adds nothing that is not.
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).toMatch(/Repair display names/)
      expect(text).toMatch(/adds nothing that was never indexed|never indexed/i)
      // How it ends is in the audit log; the screen is never told.
      expect(text).toMatch(/audit log/i)
    })

    it('separates a floored count from rows that are missing', () => {
      // `count_is_lower_bound` has three causes and two of them bound only the
      // COUNT: the walk still enumerates every match. Only an index known to
      // be missing documents means rows are gone, and the export's verdict row
      // is what says which happened.
      const { container } = renderHelp()
      const text = sectionText(container, 'search')
      expect(text).toMatch(/at least/i)
      expect(text).toMatch(/floor/i)
      expect(text).toMatch(/prevalence/i)
      expect(text).toMatch(/bounds the counting|counting.{0,40}not the walking/i)
    })
  })

  describe('review ledger section', () => {
    it('keeps opened and reviewed as two claims and never adds them', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/Opening a record is not examining it/i)
      expect(text).toMatch(/never added/i)
      expect(text).toMatch(/subset/i)
    })

    it('says the ledger is stored with the case and attributed to the examiner', () => {
      // It used to be this browser's localStorage, which answered the handover
      // question with "nothing". Every mark is now a row in the case, filed
      // under the examiner the API authenticated, and visible to everyone.
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/stored with the case on the server/i)
      expect(text).toMatch(/every examiner/i)
      expect(text).toMatch(/review history/i)
    })

    it('says an attribution is a stamped reading that nothing refreshes on its own', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/who\?/i)
      expect(text).toMatch(/UTC/)
      expect(text).toMatch(/nothing re-reads|does not re-read|never re-reads/i)
      // A press, not hover and not focus: one request per row, and a table
      // draws hundreds.
      expect(text).toMatch(/press/i)
    })

    it('says an unread row reads as not known, never as unopened', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/not known/i)
      expect(text).toMatch(/ceiling/i)
    })

    it('documents the driven re-read, and that it names the parts it covered', () => {
      // Nothing retries on its own; the button asks only for the parts that
      // are unread and the panel dates each of the four separately.
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/Read the ledger again/)
      expect(text).toMatch(/only the parts|parts that could not be read/i)
      expect(text).toMatch(/when each part was read|says when each/i)
    })

    it('refuses a percentage and says why', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/not a percentage|no percentage|never a proportion/i)
      expect(text).toMatch(/floor/i)
    })

    it('says the ledger is not the audit log, and how the two relate', () => {
      // The audit log takes one summarising row per batch
      // (`artifact_reviews_recorded`); the per-record detail is in the review
      // history, written in the same transaction as the mark. One hash-chained
      // audit row per opening would bury every deliberate act in the case.
      const { container } = renderHelp()
      const text = sectionText(container, 'review-ledger')
      expect(text).toMatch(/not the audit log/i)
      expect(text).toMatch(/what was looked at, not what was found/i)
      expect(text).toMatch(/artifact_reviews_recorded/)
    })
  })

  describe('navigation section', () => {
    it('lists every rail item the product actually ships', () => {
      // The help enumerated the Analyse group by hand and stopped at
      // Duplicates, so the five surfaces that joined the rail -- the ones an
      // inheriting examiner is most likely never to open -- were undocumented
      // in the one place they would have looked them up.
      const { container } = renderHelp()
      const text = sectionText(container, 'navigation')
      for (const item of NAV_SECTIONS.flatMap((s) => s.items)) {
        expect(text, `nav item "${item.label}" missing from the help`).toContain(
          item.label,
        )
      }
    })

    it('says the subject views are reachable three ways', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'navigation')
      expect(text).toMatch(/three ways/i)
      // The palette matches the words an examiner says, not only the label.
      expect(text).toMatch(/chats/i)
      expect(text).toMatch(/prefetch/i)
    })

    it('says Videos and Audio are not rail rows, so their absence is not a lack', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'navigation')
      expect(text).toMatch(/Videos/)
      expect(text).toMatch(/Audio/)
    })

    it('states that each view has one address, and that an older link redirects', () => {
      // S3/S4: a URL in a handover note or a witness statement has to be one
      // the reader can paste. Two addresses for one view is what that change
      // removed, and the help is where an examiner learns which one is which.
      const { container } = renderHelp()
      const text = sectionText(container, 'navigation')
      expect(text).toMatch(/one address/i)
      expect(text).toMatch(/workbench\?view=/)
    })

    it('says a mistyped case address keeps the case shell', () => {
      const { container } = renderHelp()
      const text = sectionText(container, 'navigation')
      expect(text).toMatch(/quotes the address that matched nothing/i)
    })
  })

  it('documents the actual admin bootstrap behavior, not a generic placeholder', () => {
    // Regression: the old copy ("credentials come from the deployment
    // environment") didn't describe the real loopback-default/forced-change
    // flow. Must name the default password and the forced change.
    renderHelp()
    expect(screen.getByText(/SEANCE_ADMIN_PASSWORD/)).toBeInTheDocument()
    expect(
      screen.getByText(/must change its password before doing anything else/),
    ).toBeInTheDocument()
  })

  it('mentions Volume Shadow Copy parsing', () => {
    renderHelp()
    expect(screen.getByText(/Volume Shadow Copies/)).toBeInTheDocument()
  })

  it('documents the grouped sidebar and the record provenance features', () => {
    // The sidebar was regrouped and two provenance features shipped (a RAM tag
    // on capture sources, a Source filter on the Logical lens + System Info).
    // Assert the load-bearing claims so the docs cannot silently drift from the
    // UI they describe.
    renderHelp()
    // Memory filed under Evidence as acquired evidence, not a tool.
    expect(
      screen.getByText(/acquired evidence — an image with a hash/i),
    ).toBeInTheDocument()
    // The Logical lens' source filter rescopes counts per acquisition.
    expect(screen.getByText(/rescopes every\s+count/i)).toBeInTheDocument()
    // System Info can be read one machine at a time.
    expect(
      screen.getByText(/read one machine at a time/i),
    ).toBeInTheDocument()
  })

  it('says where a bookmark can be captured, and that the note is captured with it', () => {
    // `BookmarkControl` opens a category + note form anchored to itself, on the
    // artifact page and on every Communications row; the gallery captures from
    // a cell's right-click menu and from `b`. "From its viewer" alone
    // understates it by two surfaces and misses the reason the form exists.
    const { container } = renderHelp()
    const text = sectionText(container, 'bookmarks')
    expect(text).toMatch(/Communications/)
    expect(text).toMatch(/gallery/i)
    expect(text).toMatch(/Esc/)
  })

  it('does not advise raising the page size before an export', () => {
    // Stale advice: no export in the product exports the page on screen. The
    // timeline export streams every event matching the filters, the search
    // export walks the whole match set, the audit export carries the filters,
    // and the file-browser exports carry a selection. Raising the rows per page
    // changes none of them, and following the advice on a large case costs the
    // examiner a slow page for nothing.
    const { container } = renderHelp()
    const text = sectionText(container, 'tips')
    expect(text).not.toMatch(/rows-per-page limit before exporting/i)
    expect(text).toMatch(/not the page you are looking at/i)
  })

  it('names the timeline body-file export and says it is the events, with the filters', () => {
    // Toolbar.tsx "Export body file" -> GET /timeline/export/body_events. Unlike
    // the Files page's file-list body file it HONOURS the timeline filters, and
    // its last line counts events; help must say both and must not call it the
    // file list.
    const { container } = renderHelp()
    const text = sectionText(container, 'timeline')
    expect(text).toMatch(/Export body file/)
    expect(text).toMatch(/memory events/i)
    expect(text).toMatch(/filters? you have applied|honours the filters/i)
    expect(text).toMatch(/one time/i)
    expect(text).toMatch(/Files page/)
  })

  it('names the mactime body-file export on the Files page and says it is the whole case', () => {
    // GET /cases/{id}/timeline/export/body once had no control, and this test
    // asserted help stayed silent about it. The Files page now reaches it; the
    // claim must match the button: every file in the case, from every source,
    // with none of the page's filters applied.
    const { container } = renderHelp()
    const text = sectionText(container, 'file-browser')
    expect(text).toMatch(/Export whole case as mactime body file/)
    expect(text).toMatch(/every file in the case/i)
    expect(text).toMatch(/not the filters/i)
    // A whole file can still say INCOMPLETE; help must not promise "saved"
    // for it (FileGridPage.exportCaseBodyFile).
    expect(text).toMatch(/saved only when the line reads\s*COMPLETE/i)
    expect(text).toMatch(/INCOMPLETE/)
  })

  it('describes the artifact Timeline tab and says a capped list is not the whole history', () => {
    // GET /cases/{id}/timeline/related/{artifact} had no caller; the artifact
    // page's Timeline tab now reaches it. The route is bounded and returns a
    // child's and a sibling's events without saying which, so help says both.
    const { container } = renderHelp()
    const text = sectionText(container, 'file-browser')
    expect(text).toMatch(/Timeline tab/)
    expect(text).toMatch(/parent/i)
    expect(text).toMatch(/child or sibling/i)
    expect(text).toMatch(/not the whole history/i)
  })

  it('names the records CSV export and what it covers', () => {
    // Regression: /records/export/csv shipped with no control reaching it.
    // The claim here has to match the button: the whole type, not a
    // viewer's narrowed rows.
    const { container } = renderHelp()
    const text = sectionText(container, 'analysis-records')
    expect(text).toMatch(/Export all as CSV/)
    expect(text).toMatch(/whole type, not the rows/)
  })

  it('names the XLSX report export beside HTML and PDF', () => {
    // Regression: the /export/xlsx route shipped with no control reaching it
    // and no mention here; the dashboard now has the button.
    const { container } = renderHelp()
    expect(sectionText(container, 'reporting')).toMatch(/Export XLSX/)
    expect(sectionText(container, 'dashboard')).toMatch(/Export XLSX/)
  })

  it('names the DOCX, RTF and XML report exports, and the DOCX figure limit', () => {
    // The /export/rtf and /export/xml routes shipped with no control reaching
    // them and /export/docx landed the same way (ROADMAP §2.10); the
    // dashboard now has the buttons. The DOCX picture is SVG-only, and the
    // help must say what an older Word shows rather than imply it renders.
    const { container } = renderHelp()
    const reporting = sectionText(container, 'reporting')
    expect(reporting).toMatch(/Export DOCX/)
    expect(reporting).toMatch(/Export RTF/)
    expect(reporting).toMatch(/Export XML/)
    expect(sectionText(container, 'dashboard')).toMatch(/Export DOCX/)
    expect(reporting).toMatch(/older Word shows an empty picture frame/)
    expect(reporting).toMatch(/table beneath carries the numbers/)
  })

  it('describes the SQL editor as the route enforces it, and the history as browser-local', () => {
    // HELP_SYNC Layer 2: the paragraph was first written before the route
    // existed. It may only state what POST /cases/:id/sqlite/query does.
    const { container } = renderHelp()
    const text = sectionText(container, 'analysis-records')
    expect(text).toMatch(/read-only/)
    expect(text).toMatch(/staged/)
    expect(text).toMatch(/SQLite never opens the evidence file/)
    expect(text).toMatch(/this browser only/)
    expect(text).toMatch(/at most 512 MiB/)
    expect(text).toMatch(/at most 10\s+seconds/)
    expect(text).toMatch(/never returns more than 10,000/)
    expect(text).toMatch(/audit log with the statement/)
    // The server gates in this order (seance_api run_sqlite_query_blocking):
    // sql_is_select_or_with refuses anything whose first keyword after the
    // comments is not SELECT or WITH, BEFORE SQLite sees the text; then an
    // authorizer that denies every action but Read/Select/Function/Recursive
    // (so every PRAGMA, read-only or not, is denied); then
    // sqlite3_stmt_readonly. The help must say all three, in that order.
    expect(text).toMatch(/refuses anything that is not a single\s+SELECT or\s+WITH/)
    expect(text).toMatch(/before SQLite sees it/)
    expect(text).toMatch(/every\s+PRAGMA/)
    expect(text).toMatch(/EXPLAIN/)
    expect(text).toMatch(/authorizer/)
    expect(text).toMatch(/denies every\s+PRAGMA/)
    // PRAGMA is refused by the keyword gate, not "at prepare time".
    expect(text).not.toMatch(/PRAGMA[^.]*refused at prepare time/)
  })

  it('shows recovered records apart from live ones, each with its provenance', () => {
    // Recovered EVTX events, registry cells and WMI subscriptions are their
    // own record types; the help must name them as such and must not call a
    // recovered key's path anything but an inference.
    const { container } = renderHelp()
    const text = sectionText(container, 'artifacts')
    expect(text).toMatch(/Windows Event Log \(recovered\)/)
    expect(text).toMatch(/never counted with it/)
    expect(text).toMatch(/borrowed/)
    expect(text).toMatch(/Registry keys \(recovered from unallocated cells\)/)
    expect(text).toMatch(/inference/)
    expect(text).toMatch(/not evidence that the key was\s+deleted/)
    expect(text).toMatch(/200,000 cells examined and 50,000 records/)
    expect(text).toMatch(/Autostart entries \(ASEP, recovered\)/)
    expect(text).toMatch(/INDEX\.BTR/)
  })

  it('says what the shell item, jump list and YARA records do and do not establish', () => {
    const { container } = renderHelp()
    const text = sectionText(container, 'artifacts')
    // A zero file reference is withheld, never published as entry 0.
    expect(text).toMatch(/not.*reported as\s+entry 0/)
    // The field at offset 116 is never called an access count.
    expect(text).toMatch(/offset 116/)
    expect(text).toMatch(/never called an access count/)
    expect(text).not.toMatch(/the access count/)
    // YARA: the eight surfaces of seance_plugin_yara Surface::ALL, named
    // as the code stamps them; slack scanned only where the parser published
    // a region, and a string crossing its edge not found there; "file" is
    // the narrow case.
    expect(text).toMatch(/alternate data streams/)
    expect(text).not.toMatch(/Slack is\s+not scanned/)
    expect(text).toMatch(/eight surfaces/)
    expect(text).toMatch(/volume and\s+slack/)
    expect(text).toMatch(/crosses its edge[^.]*is not found there/)
    // The lead-in list of what YARA reaches names slack too.
    expect(text).toMatch(/deleted files,\s+file slack\s+and whole volumes/)
    // Every kind of slack the producer skipped is named, and a run with no
    // slack hit points at the summary rather than reading as "none".
    expect(text).toMatch(/could not be read in full/)
    expect(text).toMatch(/250,000/)
    expect(text).toMatch(/content_incomplete/)
    expect(text).toMatch(/could not look/)
    // The slack offset is into the file system, not the evidence.
    expect(text).toMatch(/into the file system, not the evidence/)
    expect(text).toMatch(/carved/)
    expect(text).toMatch(/deleted_file/)
    expect(text).toMatch(/volume/)
    expect(text).toMatch(/registry_value/)
    expect(text).toMatch(/unallocated/)
    expect(text).toMatch(/file is\s+the narrow case/)
    // A carved object, a deleted file or a whole volume is never stamped
    // `file`; the help must not say it is.
    expect(text).not.toMatch(/whole volume[^.]*stamped\s+file/)
    expect(text).not.toMatch(/does not\s+establish that the bytes are content a file system serves/)
    expect(text).toMatch(/entropy/)
    // The feature histogram's cap is disclosed with its number (the feature
    // scanner is documented under carving and recovery).
    const carving = sectionText(container, 'carving')
    expect(carving).toMatch(/Feature histograms/)
    expect(carving).toMatch(/100,000 distinct values/)
    expect(carving).toMatch(/distinct total is a floor/)
  })

  it('names the iOS Safari and HealthKit bounds, and the schema warning', () => {
    const { container } = renderHelp()
    const text = sectionText(container, 'mobile')
    expect(text).toMatch(/schema version 43/)
    expect(text).toMatch(/capped at 500 entries/)
    expect(text).toMatch(/not which engine served/)
    expect(text).toMatch(/Only three sample\s+types are named/)
    expect(text).toMatch(/no canonical unit is guessed/)
    expect(text).toMatch(/Parser schema warnings/)
    // Two schema-warning paths exist and the help must not merge them. Since
    // HUNT-186 both read user_version 0 as "not recorded" and an unreadable
    // pragma as "undetermined"; the shared
    // seance_sqlite_util::stale::check_schema_version path the iOS Safari and
    // HealthKit parsers use still carries no table, field or record count.
    expect(text).toMatch(/never ranked as older than the range/)
    expect(text).toMatch(/Safari and HealthKit/)
    expect(text).toMatch(/never as older than the range/)
    expect(text).toMatch(/reported as\s+undetermined/)
    expect(text).not.toMatch(/is compared as a version/)
    expect(text).not.toMatch(/file no warning at all/)
    expect(text).toMatch(/no table, no field list and no record count/)
    // HUNT-204: every range-bearing warning names its evidence file.
    expect(text).toMatch(/also names the real file\(s\) the range was\s+read from/)
    expect(text).not.toMatch(/carry the range without the file name/)
    expect(text).not.toMatch(/every parser[^.]*never ranked/)
  })

  it('states the Linux path scope and the Windows kernel-structure bounds', () => {
    const { container } = renderHelp()
    const text = sectionText(container, 'memory-analysis')
    expect(text).toMatch(/mount crossing/)
    expect(text).toMatch(/dentry tree relative/)
    expect(text).toMatch(/not a path\s+in any mount/)
    expect(text).toMatch(/not made/)
    expect(text).not.toMatch(/Triggers blob is\s+not decoded/)
    expect(text).toMatch(/when it fires from the\s+Triggers blob/)
    expect(text).toMatch(/local wall-clock\s+time, never UTC/)
    expect(text).toMatch(/POSSIBLE XTS pair/)
    // The VeraCrypt positive path was graded on a real capture (one mounted AES
    // volume); help states exactly that scope, not the earlier synthetic-only one.
    expect(text).toMatch(/validated on captures with mounted\s+VeraCrypt AES, Serpent, Twofish, Camellia, Kuznyechik and cascade\s+volumes \(forty-eight product versions,\s+VeraCrypt 1\.0e to 1\.26\.30 and TrueCrypt 6\.0 to 7\.2/)
    expect(text).toMatch(/every capture is a Windows 11 build 26200 guest except three on Windows Server 2022 build 20348\.587 \(VeraCrypt 1\.26\.14, 1\.26\.18 and 1\.26\.29\), two on Windows Server 2019 build 17763 \(VeraCrypt 1\.26\.29 and 1\.26\.30\) and one on Windows 10 build 14393/)
    expect(text).not.toMatch(/validated only on a\s+synthetic region/)
    expect(text).toMatch(/never as an image with no version/)
  })

  it('states how a macOS keychain secret is revealed and what is not', () => {
    const { container } = renderHelp()
    const text = sectionText(container, 'encryption')
    expect(text).toMatch(/Revealing a macOS keychain secret/)
    expect(text).toMatch(/Reveal secret.*sends the keychain password/s)
    expect(text).toMatch(/for that one request and keeps it nowhere/)
    expect(text).toMatch(/macos_keychain_secret_revealed/)
    expect(text).toMatch(/macos_keychain_reveal_refused/)
    expect(text).toMatch(/Password items and private\s+keys are decrypted/)
  })

  it('splits the Enter-key shortcut per table rather than combining them', () => {
    // Regression: Enter navigates in the file browser and the two record
    // tables, but only expands the row inline in the timeline and the audit
    // log -- one combined row was misleading for at least two of the five.
    const { container } = renderHelp()
    const text = sectionText(container, 'shortcuts')
    expect(text).toMatch(
      /opens the row.s artifact, or, in folder view, descends into a folder/,
    )
    expect(text).toMatch(/expands the event.s details in place/)
  })

  it('collapses the TOC groups into an accordion — one open at a time', async () => {
    renderHelp()
    const toc = screen.getByRole('navigation', { name: /contents/i })

    // First group (Foundations) is open by default.
    expect(
      within(toc).getByRole('link', { name: 'Getting started' }),
    ).toBeInTheDocument()
    // A different group's items are hidden until its header is opened.
    expect(
      within(toc).queryByRole('link', { name: 'Timeline analysis' }),
    ).toBeNull()

    await userEvent.click(
      within(toc).getByRole('button', { name: /Analysis/i }),
    )
    // The Analysis group's items now show...
    expect(
      within(toc).getByRole('link', { name: 'Timeline analysis' }),
    ).toBeInTheDocument()
    // ...and the previously-open group has collapsed (one open at a time).
    expect(
      within(toc).queryByRole('link', { name: 'Getting started' }),
    ).toBeNull()
  })

  it('searches help: filters the TOC and hides non-matching sections', async () => {
    const { container } = renderHelp()
    // Pasted, not typed: every keystroke re-filters all of the help, which took
    // 4-5 s a test on the CI runners and hit the 5 s limit.
    await userEvent.click(screen.getByRole('searchbox', { name: /search help/i }))
    await userEvent.paste('prefetch')

    const toc = screen.getByRole('navigation', { name: /contents/i })
    // Sections that mention prefetch appear as results...
    expect(
      within(toc).getByRole('link', { name: 'Timeline analysis' }),
    ).toBeInTheDocument()
    // ...an unrelated section is neither listed nor visible.
    expect(
      within(toc).queryByRole('link', { name: 'Keyboard shortcuts' }),
    ).toBeNull()
    await waitFor(() =>
      expect(container.querySelector('#shortcuts')).not.toBeVisible(),
    )
    expect(container.querySelector('#timeline')).toBeVisible()

    // Clearing the search restores the accordion and all sections.
    await userEvent.clear(
      screen.getByRole('searchbox', { name: /search help/i }),
    )
    await waitFor(() =>
      expect(container.querySelector('#shortcuts')).toBeVisible(),
    )
  })

  it('shows an empty state when nothing matches the search', async () => {
    renderHelp()
    // Pasted, not typed: every keystroke re-filters all of the help, which took
    // 4-5 s a test on the CI runners and hit the 5 s limit.
    await userEvent.click(screen.getByRole('searchbox', { name: /search help/i }))
    await userEvent.paste('zzzznotathing')
    expect(screen.getByText(/no matching sections/i)).toBeInTheDocument()
  })

  it('highlights the active section in the menu', async () => {
    renderHelp()
    const toc = screen.getByRole('navigation', { name: /contents/i })
    const link = within(toc).getByRole('link', { name: 'Getting started' })
    expect(link).not.toHaveAttribute('aria-current')
    await userEvent.click(link)
    expect(link).toHaveAttribute('aria-current', 'true')
    expect(link).toHaveClass('help-toc-active')
  })

  it('returns to the previous screen with the Back button', async () => {
    render(
      <MemoryRouter
        initialEntries={['/cases/1/dashboard', '/cases/1/help']}
        initialIndex={1}
      >
        <Routes>
          <Route
            path="/cases/1/dashboard"
            element={<div>dashboard-screen</div>}
          />
          <Route path="/cases/1/help" element={<HelpPage />} />
        </Routes>
      </MemoryRouter>,
    )
    expect(screen.getByRole('heading', { name: 'Getting started' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /back/i }))
    expect(await screen.findByText('dashboard-screen')).toBeInTheDocument()
  })
})

describe('filesystems and containers facts', () => {
  it('states that ISO 9660 discs are named from their Joliet tree when present', () => {
    // COMPARISON.md claims "ISO9660 / Joliet"; the parser read only the
    // primary tree until DOC-013. The help must state the capability the code
    // now asserts, and the fact that the name's source is recorded.
    const { container } = renderHelp()
    const text = sectionText(container, 'filesystems')
    expect(text).toMatch(/Joliet/)
    expect(text).toMatch(/which tree its name came from/)
  })
})

describe('memory credential facts', () => {
  it('states that credential values are decrypted, masked, and released only by an audited reveal', () => {
    // HELP-004. This paragraph said the lens "does not decrypt any of it, so no
    // password, hash or secret value is recovered" — the same sentence MEM-008
    // falsified in the API's own stage description and which was corrected
    // there and not here. The product recovers the boot key and decrypts local
    // NT hashes, LSA secrets and cached domain logons, so the help told an
    // examiner that a capture holding decrypted hashes held none.
    const { container } = renderHelp()
    const text = sectionText(container, 'memory-analysis')
    expect(text).toMatch(/boot key is recovered/)
    expect(text).toMatch(/NT hashes are decrypted/)
    expect(text).not.toMatch(/no\s+password, hash or secret value is recovered/)
    // And what a recovered value may do: masked in listings, audited on reveal.
    expect(text).toMatch(/masked wherever it is listed/)
    expect(text).toMatch(/writes an audit event/)
  })

  it('states that a hash you already hold finds its record without printing it back', () => {
    // SEC-004, decided 2026-09-08: the value stays in the search index so the
    // cross-case pivot works. A capability the product has and does not state
    // is one an examiner does not use, and the withholding is half the point.
    const { container } = renderHelp()
    const text = sectionText(container, 'memory-analysis')
    expect(text).toMatch(/a hash you already hold finds the record/)
    expect(text).toMatch(/withheld instead of printing it back/)
  })
})

describe('timeline chart facts', () => {
  it('states that a swimlane colour belongs to the view, not the evidence', () => {
    // UI-015. The lane palette follows the mode, so two screenshots of one case
    // under two themes show the same lanes in different colours. An examiner
    // who does not know that reads a colour change as a data change.
    const { container } = renderHelp()
    const text = sectionText(container, 'timeline')
    expect(text).toMatch(/property of the view and not of the evidence/)
    expect(text).toMatch(/named beside its swatch/)
  })

  it('states that a focused chart is drawn at a resolution chosen for its window', () => {
    // UI-010. "It focuses the axis" was already said; what was missing is that
    // the bars are now as fine as the window deserves, which is the difference
    // between one bar a year wide and a fortnight of activity.
    const { container } = renderHelp()
    const text = sectionText(container, 'timeline')
    expect(text).toMatch(/resolution chosen\s+for that window/)
    expect(text).toMatch(/swimlanes below\s+share the window/)
  })
})

describe('search index maintenance facts', () => {
  it('states that the backfill adds missing documents, and that they carry metadata only', () => {
    // LIVE-028. The repair walks documents the index already has; the backfill
    // walks the database and adds the ones it is missing. The second half of
    // that sentence is the load-bearing one: a document built from a database
    // row has no file text behind it, so an empty keyword search over a
    // backfilled file must not be read as the term being absent from the
    // evidence.
    const { container } = renderHelp()
    const text = sectionText(container, 'search')
    expect(text).toMatch(/Backfill missing documents/)
    expect(text).toMatch(/metadata only/)
    expect(text).toMatch(/not found until the evidence is re-ingested/)
    expect(text).toMatch(/search_index_backfill_completed/)
  })
})

describe('timestamp and account facts', () => {
  it('states that only a pattern no ordinary operation produces asserts timestomping', () => {
    // HUNT-051. The panel used to put a tampering verdict on a sixth of a
    // stock Windows install; the help now says what the verdict rests on and
    // what an indicator is worth.
    const { container } = renderHelp()
    const text = sectionText(container, 'file-browser')
    expect(text).toMatch(/Possible timestomping/)
    expect(text).toMatch(/no ordinary file operation produces/)
    expect(text).toMatch(/An indicator is something to weigh, not a finding/)
  })

  it('states that local accounts and user profiles are different populations', () => {
    // LIVE-029. Reading one number as the other under-reports the inventory.
    const { container } = renderHelp()
    const text = sectionText(container, 'navigation')
    expect(text).toMatch(/local accounts/i)
    expect(text).toMatch(/ProfileList/)
    expect(text).toMatch(/under-reports the inventory/)
  })
})

describe('encryption unlock box facts', () => {
  it('names only the locked records the unlock box is offered on', () => {
    // SEC-204 review. The paragraph claimed "anything else that ingests
    // locked" could be opened from the record; UnlockPanel's UNLOCKABLE table
    // covers an encrypted iOS backup, a Signal for Android backup and a
    // WhatsApp crypt14 backup awaiting its key, nothing else.
    const { container } = renderHelp()
    const text = sectionText(container, 'encryption')
    expect(text).not.toMatch(/anything else that ingests locked/)
    expect(text).toMatch(
      /The unlock box is offered on those three locked records only — an encrypted iOS backup, a Signal for Android backup, and a WhatsApp backup still waiting for its key/,
    )
  })

  it('says the box reads the job, and the audit is what records whether the password was tested', () => {
    // SEC-204 review. The panel shows "Passphrase accepted" when the job
    // completes; a backup with nothing the password can be tested against
    // completes with no audit verdict, so the help must not let the box's
    // line stand for the verdict.
    const { container } = renderHelp()
    const text = sectionText(container, 'encryption')
    expect(text).toMatch(/The box reads the job, not the audit verdict/)
    expect(text).toMatch(/the audit log records no verdict/)
  })
})
