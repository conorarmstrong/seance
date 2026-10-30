import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { FileTree } from './FileTree'
import type { FileRow } from './types'

const CASE_ID = 'case-1'
const SOURCE_ID = 'source-1'

function row(partial: Partial<FileRow> & { id: string; name: string; path: string }): FileRow {
  return {
    parent_id: SOURCE_ID,
    extension: null,
    size: null,
    created: null,
    modified: null,
    accessed: null,
    is_directory: false,
    is_deleted: false,
    known_status: null,
    ...partial,
  }
}

// A small filesystem: two folders and a file at the root, and two entries
// inside /Users. Keyed by the `path` prefix the tree asks for.
const LEVELS: Record<string, FileRow[]> = {
  '': [
    row({ id: 'users', name: 'Users', path: '/Users', is_directory: true }),
    row({ id: 'windows', name: 'Windows', path: '/Windows', is_directory: true }),
    row({ id: 'boot', name: 'boot.ini', path: '/boot.ini', size: 512 }),
  ],
  '/Users': [
    row({ id: 'alice', name: 'alice', path: '/Users/alice', is_directory: true }),
    row({ id: 'bob', name: 'bob.txt', path: '/Users/bob.txt', size: 20 }),
  ],
  '/Windows': [
    row({ id: 'sys32', name: 'System32', path: '/Windows/System32', is_directory: true }),
  ],
}

function mockFilesystem() {
  server.use(
    http.get(
      `/api/v1/cases/${CASE_ID}/sources/${SOURCE_ID}/files`,
      ({ request }) => {
        const prefix = new URL(request.url).searchParams.get('path') ?? ''
        const items = LEVELS[prefix] ?? []
        return HttpResponse.json({
          items,
          total_count: items.length,
          page: 1,
          page_size: 1000,
          total_pages: 1,
          has_next: false,
          has_previous: false,
        })
      },
    ),
  )
}

function renderTree(
  handlers: { onSelect?: (r: FileRow) => void; onOpen?: (r: FileRow) => void } = {},
) {
  mockFilesystem()
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <FileTree
        caseId={CASE_ID}
        sourceId={SOURCE_ID}
        selectedId={null}
        onSelect={handlers.onSelect ?? (() => {})}
        onOpen={handlers.onOpen ?? (() => {})}
      />
    </QueryClientProvider>,
  )
}

/** The focusable treeitem carrying the given name. */
function item(name: string): HTMLElement {
  return screen.getByText(name).closest('[role="treeitem"]') as HTMLElement
}

function tabbableItems(): HTMLElement[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('[role="treeitem"][tabindex="0"]'),
  )
}

describe('FileTree keyboard contract', () => {
  it('is a single tab stop, not one per node', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    // Three rows are on screen; exactly one of them is in the tab order, so
    // Tab-ing past the tree costs one press rather than one per node.
    expect(screen.getAllByRole('treeitem')).toHaveLength(3)
    // Awaited, because the guarantee is asynchronous: `useTreeKeyboard` seeds
    // the tab stop from an effect that runs after the rows first render, so
    // there is a commit in which the rows exist and none of them is tabbable.
    // Asserting it synchronously passed on a fast machine and failed on a
    // loaded CI runner — a race in the test, not in the tree.
    await waitFor(() => expect(tabbableItems()).toHaveLength(1))
    expect(tabbableItems()[0]).toBe(item('Users'))
  })

  it('moves between visible rows with ArrowDown and ArrowUp', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()

    await userEvent.keyboard('{ArrowDown}')
    expect(item('Windows')).toHaveFocus()
    expect(tabbableItems()).toEqual([item('Windows')])

    await userEvent.keyboard('{ArrowDown}')
    expect(item('boot.ini')).toHaveFocus()
    // Clamped at the last visible row.
    await userEvent.keyboard('{ArrowDown}')
    expect(item('boot.ini')).toHaveFocus()

    await userEvent.keyboard('{ArrowUp}{ArrowUp}')
    expect(item('Users')).toHaveFocus()
    await userEvent.keyboard('{ArrowUp}')
    expect(item('Users')).toHaveFocus()
  })

  it('expands with ArrowRight and then steps into the first child', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()
    expect(item('Users')).toHaveAttribute('aria-expanded', 'false')

    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(item('Users')).toHaveAttribute('aria-expanded', 'true')
    // The first ArrowRight only opens the node; focus stays put.
    expect(item('Users')).toHaveFocus()

    await userEvent.keyboard('{ArrowRight}')
    expect(item('alice')).toHaveFocus()
  })

  it('collapses with ArrowLeft, and steps out to the parent from a child', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByText('alice')).toBeInTheDocument()
    await userEvent.keyboard('{ArrowDown}')
    expect(item('alice')).toHaveFocus()

    // From a child, ArrowLeft climbs to the parent.
    await userEvent.keyboard('{ArrowLeft}')
    expect(item('Users')).toHaveFocus()

    // From an expanded parent, ArrowLeft closes it.
    await userEvent.keyboard('{ArrowLeft}')
    expect(item('Users')).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('alice')).not.toBeInTheDocument()
    expect(item('Users')).toHaveFocus()
  })

  it('jumps to the first and last visible rows with Home and End', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()
    await userEvent.keyboard('{End}')
    expect(item('boot.ini')).toHaveFocus()
    await userEvent.keyboard('{Home}')
    expect(item('Users')).toHaveFocus()
  })

  it('type-ahead jumps to the next row whose name starts with what was typed', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()

    await userEvent.keyboard('w')
    expect(item('Windows')).toHaveFocus()

    // Keys pressed in quick succession accumulate into one search rather than
    // each starting a new one — the deep forensic paths this tree is for are
    // full of names that share a first letter. "w" then "b" is therefore "wb",
    // which matches nothing, and nothing should move.
    await userEvent.keyboard('b')
    expect(item('Windows')).toHaveFocus()

    // After a pause the next keystroke starts a fresh search, so "bo" reaches
    // boot.ini.
    await new Promise((resolve) => setTimeout(resolve, 800))
    await userEvent.keyboard('bo')
    expect(item('boot.ini')).toHaveFocus()
  })

  it('Enter toggles a folder and opens a file; Space previews a file', async () => {
    const onOpen = vi.fn()
    const onSelect = vi.fn()
    renderTree({ onOpen, onSelect })
    expect(await screen.findByText('Users')).toBeInTheDocument()

    item('Users').focus()
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('alice')).toBeInTheDocument()
    await userEvent.keyboard('{Enter}')
    await waitFor(() =>
      expect(screen.queryByText('alice')).not.toBeInTheDocument(),
    )

    item('boot.ini').focus()
    await userEvent.keyboard(' ')
    expect(onSelect).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'boot' }),
    )
    expect(onOpen).not.toHaveBeenCalled()

    await userEvent.keyboard('{Enter}')
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: 'boot' }))
  })

  it('lets a global shortcut through while focus is in the tree', async () => {
    // The rows nest, so the tree stops a key it has handled from being handled
    // again by every ancestor row on the way up. Stopping EVERY key instead
    // also stops it reaching the window, which is where the ⌘K palette and the
    // rest of the app's global shortcuts listen — so the examiner loses ⌘K for
    // as long as their focus is anywhere in the file system tree.
    const seen: string[] = []
    const listener = (event: KeyboardEvent) => {
      if (event.key === 'k') seen.push('cmd-k')
    }
    window.addEventListener('keydown', listener)
    try {
      renderTree()
      expect(await screen.findByText('Users')).toBeInTheDocument()
      item('Users').focus()

      await userEvent.keyboard('{Meta>}k{/Meta}')

      expect(seen).toEqual(['cmd-k'])
    } finally {
      window.removeEventListener('keydown', listener)
    }
  })

  it('continues the keyboard from the row clicked, not from its ancestor', async () => {
    // Rows nest, so a press inside a child bubbles through every ancestor row
    // on the way up. Whichever handler ran last would own the tab stop, which
    // means clicking a file six levels down and then pressing Tab, Shift-Tab
    // and Tab again would return the examiner to a root folder rather than to
    // the file they were reading.
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByText('bob.txt')).toBeInTheDocument()

    await userEvent.click(screen.getByText('bob.txt'))

    expect(tabbableItems()).toEqual([item('bob.txt')])
    // And the movement keys continue from there, not from /Users.
    await userEvent.keyboard('{ArrowDown}')
    expect(item('Windows')).toHaveFocus()
  })

  it('keeps a row in the tab order after the active row is collapsed away', async () => {
    renderTree()
    expect(await screen.findByText('Users')).toBeInTheDocument()
    item('Users').focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(await screen.findByText('alice')).toBeInTheDocument()
    await userEvent.keyboard('{ArrowRight}')
    expect(item('alice')).toHaveFocus()

    // Collapse the parent from the mouse, unmounting the active row. Without
    // repair the tree would have no tabbable node left and Tab would skip it
    // entirely.
    await userEvent.click(screen.getByText('Users'))
    await waitFor(() =>
      expect(screen.queryByText('alice')).not.toBeInTheDocument(),
    )
    expect(tabbableItems()).toHaveLength(1)
  })
})
