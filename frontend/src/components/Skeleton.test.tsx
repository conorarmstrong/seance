import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SkeletonList, SkeletonTable } from './Skeleton'

describe('Skeleton', () => {
  it('renders a labelled table skeleton with a header and rows', () => {
    render(<SkeletonTable rows={5} cols={4} label="Loading files" />)
    const status = screen.getByRole('status', { name: /Loading files/ })
    expect(status).toBeInTheDocument()
    // header row + 5 body rows
    expect(status.querySelectorAll('.skel-row')).toHaveLength(6)
  })

  it('renders a labelled list skeleton', () => {
    render(<SkeletonList rows={3} label="Loading tree" />)
    expect(
      screen.getByRole('status', { name: /Loading tree/ }),
    ).toBeInTheDocument()
    expect(document.querySelectorAll('.skel-line')).toHaveLength(3)
  })
})
