import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { AppsPanel } from './AppsPanel'

function mockApps(body: Record<string, unknown>) {
  server.use(
    http.get('/api/v1/cases/c1/stats/apps', () => HttpResponse.json(body)),
  )
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <AppsPanel caseId="c1" />
    </QueryClientProvider>,
  )
}

describe('AppsPanel (§2.12)', () => {
  it('groups records by application and says how each was attributed', async () => {
    mockApps({
      apps: [
        {
          app: 'WhatsApp',
          records: 4102,
          record_types: ['WhatsApp', 'WhatsAppAttachment'],
          attribution: 'record_type',
        },
        {
          app: 'chrome.exe',
          records: 88,
          record_types: ['SrumAppResourceUse'],
          attribution: 'named_by_record',
        },
      ],
      total_records: 5000,
      unattributed: {
        records: 810,
        record_types: ['FileEntry', 'RegistryHive'],
        note: '810 parsed record(s) belong to no application... NOT distributed among the applications above.',
      },
    })
    renderPanel()

    expect(await screen.findByText('WhatsApp')).toBeInTheDocument()
    // The record types behind a group are shown: an examiner seeing a big
    // number next wants to know whether it is messages, attachments or both.
    expect(
      screen.getByText('WhatsApp, WhatsAppAttachment'),
    ).toBeInTheDocument()
    // The two attributions are different confidences and say so.
    expect(screen.getByText('from the record type')).toBeInTheDocument()
    expect(screen.getByText('named by the record')).toBeInTheDocument()
  })

  it('warns that the per-app figures are not a breakdown of the case', async () => {
    mockApps({
      apps: [
        {
          app: 'Signal',
          records: 5,
          record_types: ['Signal'],
          attribution: 'record_type',
        },
      ],
      total_records: 900,
      unattributed: {
        records: 895,
        record_types: ['FileEntry'],
        note: '895 parsed record(s) belong to no application: they are artefacts of the system. They are counted here and NOT distributed among the applications above.',
      },
    })
    renderPanel()

    const note = await screen.findByTestId('an-apps-unattributed')
    expect(note).toHaveTextContent('895')
    expect(note).toHaveTextContent(/NOT distributed/)
    expect(note).toHaveClass('warn-note')
  })

  it('states plainly when every record is attributed', async () => {
    mockApps({
      apps: [
        {
          app: 'Signal',
          records: 5,
          record_types: ['Signal'],
          attribution: 'record_type',
        },
      ],
      total_records: 5,
      unattributed: {
        records: 0,
        record_types: [],
        note: 'Every parsed record in this scope is attributed to an application.',
      },
    })
    renderPanel()

    const note = await screen.findByTestId('an-apps-unattributed')
    expect(note).toHaveTextContent(/Every parsed record/)
    // Nothing is wrong, so it must not look like a warning.
    expect(note).not.toHaveClass('warn-note')
  })

  it('does not present a failed load as a device with no applications', async () => {
    server.use(
      http.get('/api/v1/cases/c1/stats/apps', () =>
        HttpResponse.json({ error: 'boom' }, { status: 500 }),
      ),
    )
    renderPanel()

    const note = await screen.findByRole('note')
    expect(note).toHaveTextContent(/Applications unavailable/)
    expect(note).toHaveTextContent(/Nothing here says this case holds no/)
  })
})
