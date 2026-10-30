import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { GenericViewer, VIEWERS, genericKeyRank } from './viewers'
import type { ParsedRecord } from './api'

/**
 * UI-028. The DNS view of the Nitroba capture — 2,905 records, and the question
 * the case turns on is "which host looked up sendanonymousemail.net?" — showed
 * transaction id, opcode, rcode and three booleans. Not the name looked up, not
 * the client that looked it up, not the time. Every field was in the record.
 */
const dns = (over: Record<string, unknown> = {}): ParsedRecord => ({
  id: 'r1',
  artifact_id: 'a1',
  metadata: {
    type: 'DnsResolution',
    name: 'www.sendanonymousemail.net',
    transaction_id: 0,
    is_response: false,
    opcode: 0,
    opcode_name: 'query',
    rcode: 0,
    rcode_name: 'NOERROR',
    resolved: false,
    tc: false,
    answer_data: ['69.80.225.91'],
    client_ip: '192.168.15.4',
    server_ip: '192.168.1.254',
    timestamp: '2008-07-22T06:01:26.436752Z',
    ...over,
  },
}) as unknown as ParsedRecord

function show(node: React.ReactNode) {
  return render(<MemoryRouter>{node}</MemoryRouter>)
}

describe('the DNS viewer', () => {
  it('answers who looked up what, and when', () => {
    const Viewer = VIEWERS.DnsResolution.Component
    show(<Viewer records={[dns()]} caseId="c1" type="DnsResolution" />)

    expect(screen.getByText('www.sendanonymousemail.net')).toBeInTheDocument()
    expect(screen.getByText('192.168.15.4')).toBeInTheDocument()
    // The answers are a list; a query answered twice must not show one answer,
    // and each answer is its own pivot trigger (§1.0) rather than a joined
    // string — an examiner who can see both addresses must be able to follow
    // either one across the case.
    show(<Viewer records={[dns({ answer_data: ['1.2.3.4', '5.6.7.8'] })]} caseId="c1" type="DnsResolution" />)
    for (const answer of ['1.2.3.4', '5.6.7.8']) {
      const trigger = screen.getByRole('button', { name: answer })
      expect(trigger).toHaveAttribute(
        'title',
        expect.stringContaining(`Pivot on ${answer}`),
      )
    }
  })
})

describe('the generic viewer', () => {
  it('shows what the record is about before what it merely records', () => {
    show(<GenericViewer records={[dns()]} caseId="c1" type="DnsResolution" />)
    // The name is the most identifying field a record has, and it was hidden on
    // the grounds that the table showed it. The table has no name column.
    expect(screen.getByText('www.sendanonymousemail.net')).toBeInTheDocument()
    expect(screen.getByText('192.168.15.4')).toBeInTheDocument()
  })

  it('ranks identity and time ahead of protocol trivia', () => {
    expect(genericKeyRank('name')).toBeLessThan(genericKeyRank('opcode'))
    expect(genericKeyRank('client_ip')).toBeLessThan(genericKeyRank('rcode'))
    expect(genericKeyRank('source_path')).toBeLessThan(genericKeyRank('flags'))
    expect(genericKeyRank('timestamp')).toBeLessThan(genericKeyRank('tc'))
    // An unranked key is still shown — it just comes after the ranked ones.
    expect(genericKeyRank('opcode')).toBe(genericKeyRank('whatever_this_is'))
  })
})
