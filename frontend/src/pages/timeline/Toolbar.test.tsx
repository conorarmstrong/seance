import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TimelineToolbar, type TimelineFilters } from './Toolbar'

const EMPTY: TimelineFilters = {
  search: '',
  range: '',
  from: null,
  to: null,
  modules: [],
  taggedOnly: false,
  pageSize: 100,
}

function renderToolbar(caseId: string, filters: TimelineFilters = EMPTY) {
  const onChange = vi.fn()
  const view = render(
    <TimelineToolbar
      caseId={caseId}
      filters={filters}
      moduleCounts={{}}
      totalCount={0}
      exporting={null}
      analysisFilter="all"
      onChange={onChange}
      onExport={() => {}}
      onOpenColumns={() => {}}
      onAnalysisFilterChange={() => {}}
    />,
  )
  const rerenderAs = (nextCase: string, nextFilters: TimelineFilters = EMPTY) =>
    view.rerender(
      <TimelineToolbar
        caseId={nextCase}
        filters={nextFilters}
        moduleCounts={{}}
        totalCount={0}
        exporting={null}
        analysisFilter="all"
        onChange={onChange}
        onExport={() => {}}
        onOpenColumns={() => {}}
        onAnalysisFilterChange={() => {}}
      />,
    )
  return { onChange, rerenderAs }
}

describe('TimelineToolbar search draft', () => {
  it('drops an unsubmitted draft when the case changes (B3-055)', async () => {
    const { rerenderAs } = renderToolbar('case-a')
    const box = screen.getByRole('textbox', { name: 'Search timeline' })
    await userEvent.type(box, 'chrome.exe')
    expect(box).toHaveValue('chrome.exe')

    // Case B, with no `search` in its URL. The applied search has not moved
    // (both cases have none), so an effect keyed on `filters.search` never
    // fires and a plain useState keeps the draft. Submitting it then filters
    // case B's timeline by a term chosen while reading case A, and the empty
    // result reads as "case B has no such activity".
    rerenderAs('case-b')

    expect(
      screen.getByRole('textbox', { name: 'Search timeline' }),
    ).toHaveValue('')
  })

  it('submits nothing carried over after a case change (B3-055)', async () => {
    const { onChange, rerenderAs } = renderToolbar('case-a')
    await userEvent.type(
      screen.getByRole('textbox', { name: 'Search timeline' }),
      'chrome.exe',
    )
    rerenderAs('case-b')

    const box = screen.getByRole('textbox', { name: 'Search timeline' })
    fireEvent.submit(box.closest('form') as HTMLFormElement)
    expect(onChange).toHaveBeenCalledWith({ search: null })
  })

  it('still shows the applied search of the case being opened', () => {
    const { rerenderAs } = renderToolbar('case-a')
    rerenderAs('case-b', { ...EMPTY, search: 'winword' })
    expect(
      screen.getByRole('textbox', { name: 'Search timeline' }),
    ).toHaveValue('winword')
  })
})
