// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  APP_ID_RAW_SCOPE,
  CLIPBOARD_TEXT_SCOPE,
  EMAIL_BODY_SCOPE,
  ENTROPY_SCOPE,
  RECYCLE_ORIGINAL_PATH_SCOPE,
  readScope,
  scopeLabelSuffix,
  scopeSentence,
  scopeWord,
} from './measuredScope'

describe('readScope', () => {
  it('reports a figure the producer measured whole as whole, and says nothing', () => {
    const scope = readScope(
      { entropy: 3.2, entropy_sampled: false, entropy_bytes: 2048, entropy_file_bytes: 2048 },
      ENTROPY_SCOPE,
    )
    expect(scope.state).toBe('whole')
    // A qualifier that is always on screen is one an examiner stops reading.
    expect(scopeSentence(scope, ENTROPY_SCOPE)).toBe('')
    expect(scopeWord(scope, ENTROPY_SCOPE)).toBe('')
    expect(scopeLabelSuffix(scope, ENTROPY_SCOPE)).toBe('')
  })

  it('reports a prefix sample as partial and carries the byte counts', () => {
    const scope = readScope(
      {
        entropy: 7.99,
        entropy_sampled: true,
        entropy_bytes: 196608,
        entropy_file_bytes: 4000000,
      },
      ENTROPY_SCOPE,
    )
    expect(scope.state).toBe('partial')
    expect(scope.measured).toBe(196608)
    expect(scope.total).toBe(4000000)
    expect(scopeWord(scope, ENTROPY_SCOPE)).toBe('sampled')
    expect(scopeLabelSuffix(scope, ENTROPY_SCOPE)).toBe(' (sampled)')
  })

  it("prefers the producer's own sentence over the generic one", () => {
    const note =
      'entropy was measured over the first 196608 of 4000000 bytes; it describes that prefix and not the whole file'
    const scope = readScope(
      { entropy_sampled: true, entropy_bytes: 196608, entropy_file_bytes: 4000000, entropy_note: note },
      ENTROPY_SCOPE,
    )
    expect(scopeSentence(scope, ENTROPY_SCOPE)).toBe(note)
  })

  it('states the exact byte counts when the producer wrote no sentence', () => {
    const scope = readScope(
      { entropy_sampled: true, entropy_bytes: 196608, entropy_file_bytes: 4000000 },
      ENTROPY_SCOPE,
    )
    const sentence = scopeSentence(scope, ENTROPY_SCOPE)
    // Exact bytes, not a rounded human size: this is the extent of a
    // measurement offered as evidence and it has to be checkable.
    expect(sentence).toContain('196,608 bytes')
    expect(sentence).toContain('4,000,000 bytes')
    expect(sentence).toContain('not the file')
  })

  it("reports a figure as partial when the producer's own counts say so and its flag does not", () => {
    // `entropy_sampled` compares the 192 KiB WINDOW with the file size, not the
    // bytes that came back. A 2 KiB file whose read fell short is stamped
    // `entropy_sampled: false` over 100 measured bytes — a figure covering 5%
    // of a file, declared as covering all of it. The counts are the checkable
    // half, and a disagreement must not resolve toward the completeness claim.
    const scope = readScope(
      {
        entropy: 3.1,
        entropy_sampled: false,
        entropy_bytes: 100,
        entropy_file_bytes: 2048,
        entropy_note:
          'entropy was measured over 100 byte(s); 2048 were requested and the rest could not be read, so the figure describes only the bytes that were there',
      },
      ENTROPY_SCOPE,
    )
    expect(scope.state).toBe('partial')
    expect(scopeWord(scope, ENTROPY_SCOPE)).toBe('sampled')
    // And the sentence is the producer's, which names what actually happened.
    expect(scopeSentence(scope, ENTROPY_SCOPE)).toContain('could not be read')
    // The class bar is separated too: a class off 100 bytes is not a class off
    // the file.
    expect(scopeLabelSuffix(scope, ENTROPY_SCOPE)).toBe(' (sampled)')
  })

  it('leaves a figure whole when the counts agree that it covered everything', () => {
    const scope = readScope(
      { entropy_sampled: false, entropy_bytes: 2048, entropy_file_bytes: 2048 },
      ENTROPY_SCOPE,
    )
    expect(scope.state).toBe('whole')
  })

  it('names what a truncated email body costs the examiner', () => {
    // The parser appends a `...[truncated]` sentinel inside the text, which its
    // own source calls prose the UI does not read. The structured flag is the
    // one the reading pane has to answer to.
    const cut = readScope({ body_text: 'Dear Bob', body_truncated: true }, EMAIL_BODY_SCOPE)
    expect(cut.state).toBe('partial')
    expect(scopeWord(cut, EMAIL_BODY_SCOPE)).toBe('truncated')
    expect(scopeSentence(cut, EMAIL_BODY_SCOPE)).toContain('not evidence it was never written')
    // A message the parser recorded whole says nothing.
    expect(readScope({ body_truncated: false }, EMAIL_BODY_SCOPE).state).toBe('whole')
    // And a record that predates the flag is not reported as whole.
    expect(readScope({ body_text: 'Dear Bob' }, EMAIL_BODY_SCOPE).state).toBe('undeclared')
  })

  it('reports a missing flag from an always-declaring producer as undeclared, never whole', () => {
    // A record that predates the declaration. Silence is not a claim of
    // completeness, and rendering it as one is the whole defect.
    const scope = readScope({ entropy: 7.99, entropy_classification: 'high' }, ENTROPY_SCOPE)
    expect(scope.state).toBe('undeclared')
    expect(scopeWord(scope, ENTROPY_SCOPE)).toBe('scope not stated')
    expect(scopeSentence(scope, ENTROPY_SCOPE)).toContain('does not declare')
  })

  it('reports an unreadable flag as undeclared, never whole', () => {
    for (const bad of [0, 'yes', {}, []]) {
      const scope = readScope({ entropy_sampled: bad }, ENTROPY_SCOPE)
      expect(scope.state).toBe('undeclared')
    }
  })

  it('accepts stringified booleans, because JSON transport may have stringified them', () => {
    expect(readScope({ entropy_sampled: 'true' }, ENTROPY_SCOPE).state).toBe('partial')
    expect(readScope({ entropy_sampled: 'false' }, ENTROPY_SCOPE).state).toBe('whole')
  })

  it('treats a missing flag as whole only for a producer that stamps it solely when true', () => {
    // The recycle-bin parser writes `original_path_truncated` only on a short
    // record, so its absence IS the parser saying the path is whole. Reading it
    // like the entropy flag would put a warning on every recycle-bin row.
    expect(readScope({ original_path: 'C:\\x.docx' }, RECYCLE_ORIGINAL_PATH_SCOPE).state).toBe(
      'whole',
    )
    expect(
      readScope({ original_path: 'C:\\x', original_path_truncated: true }, RECYCLE_ORIGINAL_PATH_SCOPE)
        .state,
    ).toBe('partial')
  })

  it('reports no scope at all for absent metadata', () => {
    expect(readScope(null, ENTROPY_SCOPE).state).toBe('undeclared')
    expect(readScope(undefined, CLIPBOARD_TEXT_SCOPE).state).toBe('undeclared')
  })

  it('names what a truncated clipboard capture and AppId cost the examiner', () => {
    const clip = readScope(
      { clipboard_text_truncated: true, clipboard_bytes: 40960 },
      CLIPBOARD_TEXT_SCOPE,
    )
    expect(scopeWord(clip, CLIPBOARD_TEXT_SCOPE)).toBe('truncated')
    expect(scopeSentence(clip, CLIPBOARD_TEXT_SCOPE)).toContain('not evidence it was not copied')

    const appId = readScope({ app_id_raw_truncated: true }, APP_ID_RAW_SCOPE)
    expect(scopeSentence(appId, APP_ID_RAW_SCOPE)).toContain('not the full set')
  })
})
