import { describe, expect, it } from 'vitest'
import { buildContactIndex } from './contactNames'

describe('buildContactIndex', () => {
  const index = buildContactIndex([
    {
      display_name: 'Deni Novak',
      phone_numbers: ['728 039 692'],
      emails: ['Deni@Example.com'],
    },
    { display_name: 'Photofilm', phone_numbers: ['728888881'], emails: [] },
    { display_name: 'No Name Fields' },
  ])

  it('matches a chat handle in E.164 against a nationally-stored number', () => {
    // The chat records +420728039692; the address book stores 728 039 692.
    expect(index.lookup('+420728039692')).toBe('Deni Novak')
    expect(index.lookup('728039692')).toBe('Deni Novak')
    expect(index.lookup('+420 728 888 881')).toBe('Photofilm')
  })

  it('treats a WhatsApp JID as the phone number it is, not an email', () => {
    // The '@' makes it look like an address, but the local part is a number.
    expect(index.lookup('420728039692@s.whatsapp.net')).toBe('Deni Novak')
    expect(index.lookup('420728888881@s.whatsapp.net')).toBe('Photofilm')
  })

  it('matches emails case-insensitively', () => {
    expect(index.lookup('deni@example.com')).toBe('Deni Novak')
  })

  it('returns null rather than guessing', () => {
    expect(index.lookup('+420999999999')).toBeNull()
    expect(index.lookup('fiobanka')).toBeNull()
    expect(index.lookup(null)).toBeNull()
    // Too short to identify anyone; a 4-digit shortcode must not match a
    // contact whose number happens to end the same way.
    expect(index.lookup('9692')).toBeNull()
  })

  it('keeps the first name for a duplicated number', () => {
    const dup = buildContactIndex([
      { display_name: 'First', phone_numbers: ['5551234567'] },
      { display_name: 'Second', phone_numbers: ['5551234567'] },
    ])
    expect(dup.lookup('+15551234567')).toBe('First')
  })

  it('carries a truncation flag so a capped address book is visible (BUG-172)', () => {
    // Default: a fully-loaded book is not truncated.
    expect(index.truncated).toBe(false)
    // When the loader hit its page cap, the flag propagates to the UI.
    const capped = buildContactIndex(
      [{ display_name: 'Partial', phone_numbers: ['5550000000'] }],
      true,
    )
    expect(capped.truncated).toBe(true)
  })
})
