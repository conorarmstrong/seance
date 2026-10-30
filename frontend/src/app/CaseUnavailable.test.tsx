import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { ApiRequestError } from '../api/http'
import { CaseUnavailable, caseUnavailableCopy } from './CaseUnavailable'

/**
 * HUNT-078: with an ingest running, `GET /cases/{id}` waited out the
 * database's busy timeout and failed with 500, and the shell told the examiner
 * the case "may have been deleted". Only a 404 supports that sentence.
 */
describe('CaseUnavailable', () => {
  it('says deleted only for a 404', () => {
    const copy = caseUnavailableCopy(new ApiRequestError(404, 'RESOURCE_NOT_FOUND', 'Case not found'))
    expect(copy.deleted).toBe(true)
    expect(copy.body).toMatch(/may have been deleted/)
  })

  it('does not say deleted for a server error, and offers a retry', () => {
    const onRetry = vi.fn()
    render(
      <MemoryRouter>
        <CaseUnavailable
          error={new ApiRequestError(500, 'INTERNAL_ERROR', 'Failed to update last_accessed_at')}
          onRetry={onRetry}
        />
      </MemoryRouter>,
    )
    expect(screen.getByRole('heading')).toHaveTextContent('Case could not be loaded')
    expect(screen.queryByText(/deleted/)).not.toBeInTheDocument()
    expect(screen.getByText(/Failed to update last_accessed_at/)).toBeInTheDocument()
    expect(screen.getByText(/Nothing here shows the case is gone/)).toBeInTheDocument()
    screen.getByRole('button', { name: 'Retry' }).click()
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('treats a dropped connection the same way', () => {
    const copy = caseUnavailableCopy(new TypeError('Failed to fetch'))
    expect(copy.deleted).toBe(false)
    expect(copy.body).toMatch(/Failed to fetch/)
  })

  it('gives a 404 no retry, only the way back', () => {
    render(
      <MemoryRouter>
        <CaseUnavailable
          error={new ApiRequestError(404, 'RESOURCE_NOT_FOUND', 'Case not found')}
          onRetry={() => {}}
        />
      </MemoryRouter>,
    )
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to all cases' })).toBeInTheDocument()
  })
})
