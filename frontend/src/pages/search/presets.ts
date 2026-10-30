/**
 * Built-in regular-expression presets for common forensic selectors, matching
 * the "predefined regex library" investigators expect (FTK/EnCase ship these).
 * Patterns are written for the Rust `regex` crate the backend uses — no
 * look-around or back-references.
 */

export interface RegexPreset {
  id: string
  label: string
  description: string
  pattern: string
}

export const REGEX_PRESETS: RegexPreset[] = [
  {
    id: 'email',
    label: 'Email address',
    description: 'Standard email addresses',
    pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
  },
  {
    id: 'ipv4',
    label: 'IPv4 address',
    description: 'Dotted-quad IPv4 addresses',
    pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',
  },
  {
    id: 'url',
    label: 'URL',
    description: 'http(s) URLs',
    pattern: 'https?://[^\\s"\'<>]+',
  },
  {
    id: 'ssn',
    label: 'US SSN',
    description: 'US Social Security numbers (NNN-NN-NNNN)',
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
  },
  {
    id: 'ccn',
    label: 'Credit-card number',
    description: '13–16 digit card numbers, optionally grouped',
    pattern: '\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{1,4}\\b',
  },
  {
    id: 'phone',
    label: 'Phone number (US)',
    description: 'US phone numbers, various groupings',
    pattern: '\\b(?:\\+?1[-. ]?)?\\(?\\d{3}\\)?[-. ]?\\d{3}[-. ]?\\d{4}\\b',
  },
  {
    id: 'mac',
    label: 'MAC address',
    description: 'Colon/hyphen-separated MAC addresses',
    pattern: '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b',
  },
  {
    id: 'btc',
    label: 'Bitcoin address',
    description: 'Legacy (1/3) and bech32 (bc1) Bitcoin addresses',
    pattern: '\\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\\b',
  },
]
