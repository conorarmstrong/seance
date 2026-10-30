import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { startTransition, useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { ContextMenu } from './ContextMenu'

describe('ContextMenu', () => {
  it('renders header/items/footer and fires then closes on selection', async () => {
    const onClose = vi.fn()
    const onRun = vi.fn()
    render(
      <ContextMenu
        x={10}
        y={10}
        header="WhatsApp · 5 records"
        footer="never alter the originals"
        items={[
          { label: 'Open results', onClick: vi.fn(), separatorAfter: true },
          { label: 'Run detector', note: 'manual', onClick: onRun },
          { label: 'Nope', disabled: true },
        ]}
        onClose={onClose}
      />,
    )
    expect(screen.getByRole('menu')).toBeInTheDocument()
    expect(screen.getByText('WhatsApp · 5 records')).toBeInTheDocument()
    expect(screen.getByText(/never alter the originals/)).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Nope' })).toBeDisabled()

    await userEvent.click(
      screen.getByRole('menuitem', { name: /Run detector/ }),
    )
    expect(onRun).toHaveBeenCalledOnce()
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('closes on Escape', async () => {
    const onClose = vi.fn()
    render(
      <ContextMenu x={0} y={0} items={[{ label: 'X' }]} onClose={onClose} />,
    )
    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalled()
  })
})

describe('ContextMenu keyboard behaviour', () => {
  /**
   * The menu is portalled to <body>, so with focus left on the element that
   * opened it a menu is announced that no key can reach: ArrowDown does
   * nothing and Tab jumps to whatever follows the portal in document order.
   * Any action offered only here would then be keyboard-inaccessible.
   */
  function Fixture({ onClose = () => {} }: { onClose?: () => void }) {
    const [open, setOpen] = useState(false)
    return (
      <div>
        <button onClick={() => setOpen(true)}>open menu</button>
        <button>after</button>
        {open && (
          <ContextMenu
            x={0}
            y={0}
            items={[
              { label: 'First' },
              { label: 'Unavailable', disabled: true },
              { label: 'Second' },
              { label: 'Third' },
            ]}
            onClose={() => {
              setOpen(false)
              onClose()
            }}
          />
        )}
      </div>
    )
  }

  function menuItem(name: string) {
    return screen.getByRole('menuitem', { name })
  }

  it('moves focus into the menu when it opens', async () => {
    render(<Fixture />)
    await userEvent.click(screen.getByText('open menu'))
    expect(menuItem('First')).toHaveFocus()
  })

  it('rolls through the items with the arrows, skipping disabled ones', async () => {
    render(<Fixture />)
    await userEvent.click(screen.getByText('open menu'))

    await userEvent.keyboard('{ArrowDown}')
    // 'Unavailable' cannot be chosen, so stopping on it would be a dead press.
    expect(menuItem('Second')).toHaveFocus()

    await userEvent.keyboard('{ArrowDown}')
    expect(menuItem('Third')).toHaveFocus()

    // A menu is short and circular: past the end is the beginning.
    await userEvent.keyboard('{ArrowDown}')
    expect(menuItem('First')).toHaveFocus()

    await userEvent.keyboard('{ArrowUp}')
    expect(menuItem('Third')).toHaveFocus()

    await userEvent.keyboard('{Home}')
    expect(menuItem('First')).toHaveFocus()
    await userEvent.keyboard('{End}')
    expect(menuItem('Third')).toHaveFocus()
  })

  it('gives focus back to whatever opened it', async () => {
    render(<Fixture />)
    const opener = screen.getByText('open menu')
    await userEvent.click(opener)
    expect(menuItem('First')).toHaveFocus()

    await userEvent.keyboard('{Escape}')

    // Without this the next Tab restarts from the top of the document, which
    // costs the examiner the position they had before they right-clicked.
    await waitFor(() => expect(opener).toHaveFocus())
  })
})

describe('ContextMenu focus return when the opener does not survive', () => {
  /**
   * The breadcrumb-overflow shape, which is the one caller that unmounts its
   * own opener. The `…` control is drawn only while the path is long enough to
   * collapse, so choosing an ancestor folder from the menu shortens the path
   * and removes that control in the very commit that closes the menu. Focus
   * cannot go back to it, and an implementation that tries lands on <body>.
   */
  function CollapsingBreadcrumb() {
    const [path, setPath] = useState([
      'Users',
      'john',
      'AppData',
      'Local',
      'Packages',
      'LocalCache',
    ])
    const [open, setOpen] = useState(false)
    const collapsed = path.length > 4
    const hidden = collapsed
      ? path.slice(1, path.length - 2).map((name, i) => ({ name, index: i + 1 }))
      : []
    const shown = collapsed
      ? [
          { name: path[0], index: 0 },
          ...path.slice(path.length - 2).map((name, i) => ({
            name,
            index: path.length - 2 + i,
          })),
        ]
      : path.map((name, index) => ({ name, index }))

    return (
      <nav aria-label="Current folder">
        <button type="button">Root</button>
        {shown.map(({ name, index }, position) => (
          <span key={`${name}-${index}`}>
            {collapsed && position === 1 && (
              <button type="button" onClick={() => setOpen(true)}>
                {`${hidden.length} hidden folders`}
              </button>
            )}
            <button
              type="button"
              aria-current={index === path.length - 1 ? 'page' : undefined}
              onClick={() => setPath(path.slice(0, index + 1))}
            >
              {name}
            </button>
          </span>
        ))}
        {open && (
          <ContextMenu
            x={0}
            y={0}
            header="Folders not shown in the path"
            items={hidden.map(({ name, index }) => ({
              label: name,
              onClick: () => setPath((p) => p.slice(0, index + 1)),
            }))}
            onClose={() => setOpen(false)}
          />
        )}
      </nav>
    )
  }

  it('lands on the folder the examiner chose, not on <body>', async () => {
    render(<CollapsingBreadcrumb />)
    await userEvent.click(
      screen.getByRole('button', { name: '3 hidden folders' }),
    )
    await userEvent.click(screen.getByRole('menuitem', { name: 'AppData' }))

    // The `…` control that opened the menu is gone: /Users/john/AppData is
    // three segments, so the path no longer collapses. Focus must not be
    // dropped on <body>, which restarts the next Tab at the top of the
    // document and costs a keyboard examiner the place they were standing.
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'AppData' })).toHaveFocus(),
    )
    expect(document.body).not.toHaveFocus()
  })

  it('rescues focus when the opener is removed a commit later than the menu', async () => {
    // react-router defers its own state update into a transition, so the real
    // breadcrumb shortens in a LATER commit than the one that closed the menu.
    // The opener is therefore still in the document when the menu's cleanup
    // hands focus back to it, and only afterwards does it vanish underneath
    // that focus — which drops the examiner on <body> exactly as if the
    // cleanup had done nothing at all.
    function DeferredNavigation() {
      const [path, setPath] = useState(['Users', 'john', 'AppData', 'Local'])
      const [open, setOpen] = useState(false)
      const collapsed = path.length > 3
      return (
        <nav aria-label="Current folder">
          {path.map((name) => (
            <button
              type="button"
              key={name}
              aria-current={
                name === path[path.length - 1] ? 'page' : undefined
              }
            >
              {name}
            </button>
          ))}
          {collapsed && (
            <button type="button" onClick={() => setOpen(true)}>
              2 hidden folders
            </button>
          )}
          {open && (
            <ContextMenu
              x={0}
              y={0}
              items={[
                {
                  label: 'john',
                  onClick: () =>
                    startTransition(() => setPath(['Users', 'john'])),
                },
              ]}
              onClose={() => setOpen(false)}
            />
          )}
        </nav>
      )
    }

    render(<DeferredNavigation />)
    await userEvent.click(
      screen.getByRole('button', { name: '2 hidden folders' }),
    )
    await userEvent.click(screen.getByRole('menuitem', { name: 'john' }))

    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'john' })).toHaveFocus(),
    )
    expect(document.body).not.toHaveFocus()
  })

  it('falls back to the surviving region when the chosen item names nothing on screen', async () => {
    // A caller whose menu item does not reappear as a control still must not
    // lose the examiner: focus goes to the nearest ancestor of the vanished
    // opener that is still in the document, so the next Tab resumes there.
    function VanishingOpener() {
      const [open, setOpen] = useState(false)
      const [gone, setGone] = useState(false)
      return (
        <nav aria-label="Toolbar">
          <button type="button">Stay put</button>
          {!gone && (
            <button type="button" onClick={() => setOpen(true)}>
              open menu
            </button>
          )}
          {open && (
            <ContextMenu
              x={0}
              y={0}
              items={[{ label: 'Dismiss this toolbar', onClick: () => setGone(true) }]}
              onClose={() => setOpen(false)}
            />
          )}
        </nav>
      )
    }

    render(<VanishingOpener />)
    await userEvent.click(screen.getByRole('button', { name: 'open menu' }))
    await userEvent.click(
      screen.getByRole('menuitem', { name: 'Dismiss this toolbar' }),
    )

    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Stay put' })).toHaveFocus(),
    )
  })
})
