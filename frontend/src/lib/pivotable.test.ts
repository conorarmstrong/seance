import { describe, expect, it } from 'vitest'
import { isPivotableKey, isPivotableValue, pivotTarget } from './pivotable'

describe('isPivotableKey', () => {
  it('accepts the identifier classes a case is followed by', () => {
    for (const k of [
      'md5',
      'sha256',
      'sha1_hash',
      'entry_hash',
      'imphash',
      'pdq_hash',
      'client_ip',
      'server_ip',
      'peer_address',
      'host',
      'domain',
      'url',
      'username',
      'user_sid',
      'owner',
      'email',
      'serial',
      'serial_number',
      'imei',
      'udid',
      'filename',
      'original_filename',
      'executable_name',
      'path',
      'original_path',
      'stored_path',
      'name',
      'display_name',
      'device_name',
      'package_name',
    ]) {
      expect(isPivotableKey(k), k).toBe(true)
    }
  })

  it('refuses the things a pivot would only make noise of', () => {
    for (const k of [
      // Counts, sizes, offsets.
      'size',
      'artifact_count',
      'total_bytes',
      'byte_offset',
      'record_length',
      // Flags and booleans.
      'is_directory',
      'deleted',
      'encrypted',
      // Versions and types.
      'version',
      'product_version',
      'artifact_type',
      'format',
      // Our own honesty vocabulary — prose, not evidence.
      'inventory_incomplete_reason',
      'content_incomplete_reason',
      'incomplete_detail',
      'message',
      'times_note',
      // Times, however named.
      'timestamp',
      'install_time',
      'last_written',
      'created_at',
      'modified',
      // A key nobody has classified defaults to not-pivotable.
      'rcode_name',
      'flag_names',
      'role_name',
      'mystery_field',
    ]) {
      expect(isPivotableKey(k), k).toBe(false)
    }
  })

  it('does not let a `name` fragment inside another word match', () => {
    // `^name$` and the named `*_name` list only; `rcode_name` is a protocol
    // result and `flag_names` a decoded bitfield — neither is an identifier.
    expect(isPivotableKey('name')).toBe(true)
    expect(isPivotableKey('rcode_name')).toBe(false)
    expect(isPivotableKey('flag_names')).toBe(false)
  })

  it('is case-insensitive', () => {
    expect(isPivotableKey('MD5')).toBe(true)
    expect(isPivotableKey('Client_IP')).toBe(true)
  })
})

describe('isPivotableValue', () => {
  it('takes a non-empty single-line string of reasonable length', () => {
    expect(isPivotableValue('10.0.0.5')).toBe(true)
    expect(isPivotableValue('d41d8cd98f00b204e9800998ecf8427e')).toBe(true)
    expect(isPivotableValue('  spaced  ')).toBe(true)
  })

  it('refuses what an index cannot usefully be asked about', () => {
    expect(isPivotableValue(null)).toBe(false)
    expect(isPivotableValue(undefined)).toBe(false)
    expect(isPivotableValue(4096)).toBe(false)
    expect(isPivotableValue(true)).toBe(false)
    expect(isPivotableValue({ a: 1 })).toBe(false)
    expect(isPivotableValue([1, 2])).toBe(false)
    expect(isPivotableValue('')).toBe(false)
    expect(isPivotableValue('   ')).toBe(false)
    expect(isPivotableValue('a'.repeat(257))).toBe(false)
    expect(isPivotableValue('two\nlines')).toBe(false)
  })

  it('refuses a stringified boolean or bare integer', () => {
    // These reach metadata as strings from some parsers; a pivot on "false"
    // or "0" would match half the case.
    expect(isPivotableValue('true')).toBe(false)
    expect(isPivotableValue('False')).toBe(false)
    expect(isPivotableValue('0')).toBe(false)
    expect(isPivotableValue('-17')).toBe(false)
    // A dotted quad is not a bare integer.
    expect(isPivotableValue('10.0.0.5')).toBe(true)
  })
})

describe('pivotTarget', () => {
  it('needs both an identifier key and a usable value', () => {
    expect(pivotTarget('client_ip', '10.0.0.5')).toBe('10.0.0.5')
    expect(pivotTarget('client_ip', '  10.0.0.5  ')).toBe('10.0.0.5')
    // Right key, unusable value.
    expect(pivotTarget('client_ip', 4096)).toBeNull()
    expect(pivotTarget('owner', 'false')).toBeNull()
    // Usable value, wrong key.
    expect(pivotTarget('size', '4096')).toBeNull()
    expect(pivotTarget('incomplete_detail', 'the walk stopped')).toBeNull()
  })
})
