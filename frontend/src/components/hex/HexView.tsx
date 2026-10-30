import './hex.css'

export interface HexRow {
  offset: number
  bytes: string[]
  ascii: string
}

export function splitHexRows(
  startOffset: number,
  hex: string,
  ascii: string,
): HexRow[] {
  const bytes = hex.trim() ? hex.trim().split(/\s+/) : []
  const rows: HexRow[] = []
  for (let i = 0; i < bytes.length; i += 16) {
    rows.push({
      offset: startOffset + i,
      bytes: bytes.slice(i, i + 16),
      ascii: ascii.slice(i, i + 16),
    })
  }
  return rows
}

export function HexView({
  offset,
  hex,
  ascii,
}: {
  offset: number
  hex: string
  ascii: string
}) {
  const rows = splitHexRows(offset, hex, ascii)
  if (rows.length === 0) {
    return <div className="empty-state">No data at this offset.</div>
  }
  return (
    <div className="hex-view mono">
      {rows.map((row) => (
        <div key={row.offset} className="hex-row">
          <span className="hex-offset">
            {row.offset.toString(16).padStart(8, '0')}
          </span>
          <span className="hex-bytes">
            {row.bytes.map((byte, i) => (
              <span
                key={i}
                className={byte === '00' ? 'hex-byte hex-zero' : 'hex-byte'}
              >
                {byte}
              </span>
            ))}
          </span>
          <span className="hex-ascii">{row.ascii}</span>
        </div>
      ))}
    </div>
  )
}
