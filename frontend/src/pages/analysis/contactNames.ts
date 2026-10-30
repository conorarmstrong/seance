import { useQuery } from '@tanstack/react-query'
import { getRecords, type RecordMetadata } from './api'

/**
 * Resolve chat handles to names from the device's own address book.
 *
 * A chat database stores handles, not names: iMessage shows `+420728039692`
 * where the phone showed a contact. The address book holds the mapping, but not
 * in the same format — contacts often store a national number (`728039692`)
 * while the chat stores E.164 — so numbers are compared by their trailing
 * digits.
 *
 * This is an inference from evidence, not a fact recorded in the chat, so
 * callers show the resolved name *alongside* the raw handle rather than
 * replacing it.
 */

/** Digits only, keeping the last `SIGNIFICANT` of them. */
const SIGNIFICANT = 9

function phoneKey(raw: string): string | null {
  const digits = raw.replace(/\D/g, '')
  if (digits.length < 7) return null
  return digits.slice(-SIGNIFICANT)
}

/**
 * A messaging handle reduced to what it identifies.
 *
 * WhatsApp addresses a contact as `420608142231@s.whatsapp.net` — an '@' in the
 * string, but a phone number, not an email. Treating it as an email meant the
 * address book never matched it. Anything whose part before the '@' is all
 * digits is a number; a group JID (`...@g.us`) identifies no single person.
 */
function handleKind(handle: string): { phone?: string; email?: string } {
  const at = handle.indexOf('@')
  if (at < 0) {
    const phone = phoneKey(handle)
    return phone ? { phone } : {}
  }
  const local = handle.slice(0, at)
  if (/^\d+$/.test(local)) {
    const phone = phoneKey(local)
    return phone ? { phone } : {}
  }
  return { email: handle.trim().toLowerCase() }
}

export interface ContactIndex {
  /** Name for a handle (phone or email), or null when the book has none. */
  lookup: (handle: string | null | undefined) => string | null
  size: number
  /** True when the address book was capped mid-load, so some later contacts
   *  are missing from the index and may render unnamed (BUG-172). */
  truncated: boolean
}

const EMPTY: ContactIndex = { lookup: () => null, size: 0, truncated: false }

export function buildContactIndex(
  records: RecordMetadata[],
  truncated = false,
): ContactIndex {
  const byPhone = new Map<string, string>()
  const byEmail = new Map<string, string>()

  for (const m of records) {
    const name =
      typeof m.display_name === 'string' && m.display_name.trim().length > 0
        ? m.display_name.trim()
        : null
    if (!name) continue
    const phones = Array.isArray(m.phone_numbers) ? m.phone_numbers : []
    for (const p of phones) {
      if (typeof p !== 'string') continue
      const key = phoneKey(p)
      // First writer wins: a later duplicate must not silently rename an
      // already-resolved number.
      if (key && !byPhone.has(key)) byPhone.set(key, name)
    }
    const emails = Array.isArray(m.emails) ? m.emails : []
    for (const e of emails) {
      if (typeof e !== 'string') continue
      const key = e.trim().toLowerCase()
      if (key && !byEmail.has(key)) byEmail.set(key, name)
    }
  }

  return {
    size: byPhone.size + byEmail.size,
    truncated,
    lookup: (handle) => {
      if (!handle) return null
      const { phone, email } = handleKind(handle.trim())
      if (phone) return byPhone.get(phone) ?? null
      if (email) return byEmail.get(email) ?? null
      return null
    },
  }
}

/** The case's address book, loaded once and cached. */
export function useContactIndex(caseId: string): ContactIndex {
  const query = useQuery({
    queryKey: ['contact-index', caseId],
    queryFn: async () => {
      // Page through the whole address book: a partial index silently fails to
      // name people, which reads as "the tool doesn't know them". Records are
      // small and the endpoint is indexed, so this is a few cheap calls; the
      // cap only guards a pathological case.
      const PAGE = 500
      const MAX_PAGES = 20
      const out: RecordMetadata[] = []
      let truncated = false
      for (let page = 1; page <= MAX_PAGES; page += 1) {
        const res = await getRecords(caseId, {
          type: 'Contact',
          page,
          page_size: PAGE,
        })
        out.push(...res.records.map((r) => r.metadata))
        if (out.length >= res.total || res.records.length < PAGE) break
        // Hit the page cap with more contacts still on the server: the index is
        // incomplete and must say so (BUG-172).
        if (page === MAX_PAGES && out.length < res.total) truncated = true
      }
      return { records: out, truncated }
    },
    staleTime: Infinity,
    retry: false,
  })
  return query.data
    ? buildContactIndex(query.data.records, query.data.truncated)
    : EMPTY
}
