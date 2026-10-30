import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { splitHexRows } from './HexView'
import { HexView } from './HexView'

describe('splitHexRows', () => {
  it('splits hex/ascii into 16-byte rows with offsets', () => {
    const hex = Array.from({ length: 20 }, (_, i) =>
      i.toString(16).padStart(2, '0'),
    ).join(' ')
    const ascii = '.'.repeat(20)
    const rows = splitHexRows(256, hex, ascii)
    expect(rows).toHaveLength(2)
    expect(rows[0].offset).toBe(256)
    expect(rows[0].bytes).toHaveLength(16)
    expect(rows[1].offset).toBe(272)
    expect(rows[1].bytes).toHaveLength(4)
    expect(rows[1].ascii).toBe('....')
  })

  it('handles empty input', () => {
    expect(splitHexRows(0, '', '')).toHaveLength(0)
  })
})

describe('HexView', () => {
  it('renders offsets as hex and byte pairs', () => {
    render(<HexView offset={0} hex="4d 5a 90 00" ascii="MZ.." />)
    expect(screen.getByText('00000000')).toBeInTheDocument()
    expect(screen.getByText('4d')).toBeInTheDocument()
    expect(screen.getByText('MZ..')).toBeInTheDocument()
  })
})
