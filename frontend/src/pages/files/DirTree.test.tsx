import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { DirTree } from './DirTree'
import type { FileRow } from './types'

const CASE_ID = 'case-1'
const SOURCE_ID = 'source-1'

function dir(id: string, name: string, path: string): FileRow {
  return {
    id,
    parent_id: SOURCE_ID,
    name,
    path,
    extension: null,
    size: null,
    created: null,
    modified: null,
    accessed: null,
    is_directory: true,
    is_deleted: false,
    known_status: null,
  }
}

/**
 * Serve one page of a directory level while claiming the level really holds
 * `totalCount` folders — the shape the server returns for a directory with more
 * immediate subfolders than one page.
 */
function mockLevel(items: FileRow[], totalCount: number) {
  server.use(
    http.get(
      `/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`,
      ({ request }) => {
        const prefix = new URL(request.url).searchParams.get('path') ?? ''
        const atRoot = prefix === ''
        const rows = atRoot ? items : []
        return HttpResponse.json({
          items: rows,
          total_count: atRoot ? totalCount : 0,
          page: 1,
          page_size: 500,
          total_pages: 1,
          has_next: atRoot && totalCount > rows.length,
          has_previous: false,
        })
      },
    ),
  )
}

function renderTree(onSelect: (path: string | null) => void = () => {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <DirTree
        caseId={CASE_ID}
        sourceId={SOURCE_ID}
        currentDirPath=""
        onSelect={onSelect}
      />
    </QueryClientProvider>,
  )
}

/** The focusable treeitem carrying the given folder name. */
function item(name: string): HTMLElement {
  return screen.getByText(name).closest('[role="treeitem"]') as HTMLElement
}

function tabbableItems(): HTMLElement[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('[role="treeitem"][tabindex="0"]'),
  )
}

/** Two root folders and one child under /Windows, for the keyboard tests. */
function mockNestedLevels() {
  server.use(
    http.get(
      `/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`,
      ({ request }) => {
        const prefix = new URL(request.url).searchParams.get('path') ?? ''
        const items =
          prefix === ''
            ? [dir('d1', 'Users', '/Users'), dir('d2', 'Windows', '/Windows')]
            : prefix === '/Windows'
              ? [dir('d3', 'System32', '/Windows/System32')]
              : []
        return HttpResponse.json({
          items,
          total_count: items.length,
          page: 1,
          page_size: 500,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        })
      },
    ),
  )
}

describe('DirTree', () => {
  it('says how many folders the level holds beyond the page it fetched', async () => {
    // The sidebar only ever asks for page 1. Without the note, a directory with
    // 900 subfolders renders 500 of them and looks like the whole level: an
    // examiner concludes a folder does not exist when it is merely on page 2.
    mockLevel([dir('d1', 'Windows', '/Windows')], 901)
    renderTree()

    expect(await screen.findByText('Windows')).toBeInTheDocument()
    expect(
      screen.getByText(/900 more folders not shown at this level/),
    ).toBeInTheDocument()
  })

  it('says nothing when the level is complete', async () => {
    mockLevel([dir('d1', 'Windows', '/Windows')], 1)
    renderTree()

    expect(await screen.findByText('Windows')).toBeInTheDocument()
    expect(screen.queryByText(/more folders not shown/)).toBeNull()
  })

  it('reports truncation for a nested level too, not only the root', async () => {
    server.use(
      http.get(
        `/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`,
        ({ request }) => {
          const prefix = new URL(request.url).searchParams.get('path') ?? ''
          if (prefix === '') {
            return HttpResponse.json({
              items: [dir('d1', 'Windows', '/Windows')],
              total_count: 1,
              page: 1,
              page_size: 500,
              total_pages: 1,
              has_next: false,
              has_previous: false,
            })
          }
          return HttpResponse.json({
            items: [dir('d2', 'System32', '/Windows/System32')],
            total_count: 12,
            page: 1,
            page_size: 500,
            total_pages: 1,
            has_next: true,
            has_previous: false,
          })
        },
      ),
    )
    renderTree()

    await userEvent.click(
      await screen.findByRole('button', { name: 'Expand Windows' }),
    )

    expect(await screen.findByText('System32')).toBeInTheDocument()
    expect(
      await screen.findByText(/11 more folders not shown at this level/),
    ).toBeInTheDocument()
  })

  /**
   * ext4, FAT/exFAT, XFS, btrfs and APFS stamp `directory_parse_incomplete` on
   * the folder whose entry listing they could not finish (~31 sites). The tree
   * is where an examiner decides a path is not in the evidence, so a folder
   * whose listing stopped at a cap must not render like one that really held
   * four files. Both halves are pinned: the request has to ask for the metadata
   * (without `include_metadata` the flag never arrives), and the node has to
   * render it with its reason.
   */
  it('marks a folder whose listing the filesystem parser could not finish', async () => {
    const short = dir('d1', 'Users', '/Users')
    short.metadata = {
      directory_parse_incomplete: true,
      directory_parse_incomplete_reason: 'fat_chain_incomplete',
    }
    mockLevel([short], 1)
    renderTree()

    expect(await screen.findByText('Users')).toBeInTheDocument()
    const badge = screen.getByRole('note')
    expect(badge).toHaveAccessibleName(/folder listing incomplete/i)
    expect(badge).toHaveAccessibleName(/cluster chain/i)
  })

  it('asks the server for the metadata that carries that flag', async () => {
    const seen: URLSearchParams[] = []
    server.use(
      http.get(
        `/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`,
        ({ request }) => {
          seen.push(new URL(request.url).searchParams)
          return HttpResponse.json({
            items: [dir('d1', 'Users', '/Users')],
            total_count: 1,
            page: 1,
            page_size: 500,
            total_pages: 1,
            has_next: false,
            has_previous: false,
          })
        },
      ),
    )
    renderTree()

    expect(await screen.findByText('Users')).toBeInTheDocument()
    expect(seen[0].get('include_metadata')).toBe('true')
  })

  it('marks nothing on a folder the parser read in full', async () => {
    // A marker on every folder is a marker an examiner stops seeing.
    const whole = dir('d1', 'Users', '/Users')
    whole.metadata = { name: 'Users' }
    mockLevel([whole], 1)
    renderTree()

    expect(await screen.findByText('Users')).toBeInTheDocument()
    expect(screen.queryByRole('note')).toBeNull()
  })
})

/**
 * The folder sidebar answers to the same keyboard contract as the file system
 * tree and the two navigator trees, because it is the same contract and it now
 * runs the same implementation of it (`components/tree/useTreeKeyboard`).
 *
 * Before this it announced no tree semantics at all: a screen-reader user heard
 * a list of buttons, and a sighted keyboard user paid two Tab presses per
 * folder — one for the caret, one for the label — to walk a Windows path that
 * is routinely six levels deep.
 */
describe('DirTree keyboard contract', () => {
  it('is a tree with one tab stop, not two buttons per folder', async () => {
    mockNestedLevels()
    renderTree()

    expect(await screen.findByText('Users')).toBeInTheDocument()
    expect(screen.getByRole('tree')).toBeInTheDocument()
    expect(screen.getAllByRole('treeitem')).toHaveLength(2)
    expect(tabbableItems()).toEqual([item('Users')])
  })

  it('moves between visible folders with ArrowDown and ArrowUp', async () => {
    mockNestedLevels()
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()

    await userEvent.keyboard('{ArrowDown}')
    expect(item('Windows')).toHaveFocus()
    await userEvent.keyboard('{ArrowDown}')
    expect(item('Windows')).toHaveFocus()
    await userEvent.keyboard('{ArrowUp}')
    expect(item('Users')).toHaveFocus()
  })

  it('opens a folder with ArrowRight and then steps into it', async () => {
    mockNestedLevels()
    renderTree()
    expect(await screen.findByText('Windows')).toBeInTheDocument()
    item('Windows').focus()
    expect(item('Windows')).toHaveAttribute('aria-expanded', 'false')

    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByText('System32')).toBeInTheDocument()
    expect(item('Windows')).toHaveAttribute('aria-expanded', 'true')
    expect(item('Windows')).toHaveFocus()

    await userEvent.keyboard('{ArrowRight}')
    expect(item('System32')).toHaveFocus()

    // From a child, ArrowLeft climbs out; from the open parent, it closes.
    await userEvent.keyboard('{ArrowLeft}')
    expect(item('Windows')).toHaveFocus()
    await userEvent.keyboard('{ArrowLeft}')
    expect(item('Windows')).toHaveAttribute('aria-expanded', 'false')
  })

  it('type-ahead moves to a folder by name, and nowhere on no match', async () => {
    mockNestedLevels()
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()

    await userEvent.keyboard('w')
    expect(item('Windows')).toHaveFocus()

    // Keys inside the window accumulate into one search: "wu" names nothing
    // here, and landing on whatever "u" alone matched would put the examiner
    // in a folder they did not ask for.
    await userEvent.keyboard('u')
    expect(item('Windows')).toHaveFocus()
  })

  it('Enter opens a folder in place; Space navigates the grid into it', async () => {
    // Two different destinations, matching the two things a mouse can click on
    // the row: the caret opens the folder without moving, the label moves.
    const onSelect = vi.fn()
    mockNestedLevels()
    renderTree(onSelect)
    expect(await screen.findByText('Windows')).toBeInTheDocument()
    item('Windows').focus()

    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('System32')).toBeInTheDocument()
    expect(onSelect).not.toHaveBeenCalled()

    await userEvent.keyboard(' ')
    expect(onSelect).toHaveBeenCalledWith('/Windows')
  })
})
