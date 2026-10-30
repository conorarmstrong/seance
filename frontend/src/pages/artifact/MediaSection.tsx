import { useQuery } from '@tanstack/react-query'
import { getArtifactChildrenWithMetadata } from './api'
import { metadataNumber, metadataString } from './lib'
import { CopyButton } from './MetadataTabs'

interface Field {
  label: string
  value: string
  mono?: boolean
}

/** Locate the `exif` ParsedRecord parented to this image, if one was emitted. */
function findExif(
  children: { metadata?: Record<string, unknown> }[],
): Record<string, unknown> | null {
  for (const child of children) {
    if (child.metadata && child.metadata.type === 'exif') return child.metadata
  }
  return null
}

function exifFields(exif: Record<string, unknown>): Field[] {
  const fields: Field[] = []
  const camera =
    metadataString(exif, 'camera') ??
    [metadataString(exif, 'make'), metadataString(exif, 'model')]
      .filter(Boolean)
      .join(' ')
  if (camera) fields.push({ label: 'Camera', value: camera })
  const lens = metadataString(exif, 'lens')
  if (lens) fields.push({ label: 'Lens', value: lens })
  // EXIF DateTimeOriginal is emitted verbatim ("YYYY:MM:DD HH:MM:SS", camera
  // local zone), so it is shown raw rather than through the UTC formatter.
  const taken = metadataString(exif, 'datetime_original')
  if (taken) fields.push({ label: 'Taken', value: taken, mono: true })
  const width = metadataNumber(exif, 'width')
  const height = metadataNumber(exif, 'height')
  if (width != null && height != null) {
    // `exif_declared`: the pixels could not be decoded, so this is the size the
    // EXIF header claims, not a measured one (HUNT-200).
    const declared = metadataString(exif, 'dimensions_source') === 'exif_declared'
    fields.push({
      label: declared ? 'Dimensions (declared by EXIF, not measured)' : 'Dimensions',
      value: `${width} x ${height}`,
      mono: true,
    })
  }
  // An image with no EXIF, or whose EXIF could not be read, says which.
  const status = metadataString(exif, 'metadata_status')
  if (status) fields.push({ label: 'Metadata', value: status })
  const exposure = metadataString(exif, 'exposure')
  if (exposure) fields.push({ label: 'Exposure', value: `${exposure} s`, mono: true })
  const fnumber = metadataNumber(exif, 'fnumber')
  if (fnumber != null) fields.push({ label: 'Aperture', value: `f/${fnumber}`, mono: true })
  const iso = metadataNumber(exif, 'iso')
  if (iso != null) fields.push({ label: 'ISO', value: String(iso), mono: true })
  const focal = metadataNumber(exif, 'focal_length')
  if (focal != null) {
    fields.push({ label: 'Focal length', value: `${focal} mm`, mono: true })
  }
  const software = metadataString(exif, 'software')
  if (software) fields.push({ label: 'Software', value: software })
  return fields
}

/**
 * Offline location plot: an equirectangular graticule with the GPS point
 * placed by a linear lon/lat -> viewBox mapping. The viewBox is 360x180 so
 * x = lon + 180 and y = 90 - lat directly. No external tiles are requested,
 * keeping the viewer air-gap safe.
 */
function WorldMapDot({ lat, lon }: { lat: number; lon: number }) {
  const x = lon + 180
  const y = 90 - lat
  const meridians = [60, 120, 240, 300]
  const parallels = [30, 60, 120, 150]
  return (
    <svg
      className="av-map"
      viewBox="0 0 360 180"
      role="img"
      aria-label={`Location plotted at ${lat}, ${lon}`}
    >
      <rect x="0" y="0" width="360" height="180" className="av-map-frame" />
      {meridians.map((mx) => (
        <line key={`m${mx}`} x1={mx} y1="0" x2={mx} y2="180" className="av-map-grid" />
      ))}
      {parallels.map((py) => (
        <line key={`p${py}`} x1="0" y1={py} x2="360" y2={py} className="av-map-grid" />
      ))}
      <line x1="180" y1="0" x2="180" y2="180" className="av-map-axis" />
      <line x1="0" y1="90" x2="360" y2="90" className="av-map-axis" />
      <line x1={x} y1="0" x2={x} y2="180" className="av-map-cross" />
      <line x1="0" y1={y} x2="360" y2={y} className="av-map-cross" />
      <circle cx={x} cy={y} r="4" className="av-map-dot" />
    </svg>
  )
}

/**
 * Image metadata (EXIF) block shown under an image preview. Fetches the
 * artifact's children, finds the `exif` record, and renders nothing when the
 * image has no EXIF child.
 */
export function ExifSection({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const query = useQuery({
    queryKey: ['artifact-exif', caseId, artifactId],
    queryFn: () => getArtifactChildrenWithMetadata(caseId, artifactId),
  })
  const exif = query.data ? findExif(query.data) : null
  if (!exif) return null

  const fields = exifFields(exif)
  const lat = metadataNumber(exif, 'gps_lat')
  const lon = metadataNumber(exif, 'gps_lon')
  const hasGps = exif.has_gps === true && lat != null && lon != null
  const altitude = metadataNumber(exif, 'gps_altitude')
  const coords = hasGps ? `${lat}, ${lon}` : ''

  // A dimensions mismatch means EXIF's self-declared size disagrees with the
  // decoded bitstream — evidence the metadata was edited. Surface it loudly.
  const dimsMismatch = exif.dimensions_mismatch === true
  const actualW = metadataNumber(exif, 'actual_width')
  const actualH = metadataNumber(exif, 'actual_height')
  const exifW = metadataNumber(exif, 'exif_width')
  const exifH = metadataNumber(exif, 'exif_height')

  return (
    <section className="av-exif">
      <h3 className="av-ts-title">Image metadata (EXIF)</h3>
      {dimsMismatch && actualW != null && exifW != null && (
        <div className="av-tamper" role="alert">
          <strong>⚠ Dimensions mismatch.</strong> The image decodes to{' '}
          <span className="mono">
            {actualW}×{actualH}
          </span>
          , but its EXIF metadata declares{' '}
          <span className="mono">
            {exifW}×{exifH}
          </span>
          . The EXIF size was edited and does not match the pixels.
        </div>
      )}
      {fields.length > 0 && (
        <div className="av-cards">
          {fields.map((field) => (
            <div key={field.label} className="av-card">
              <span className="av-label">{field.label}</span>
              <span className={field.mono ? 'av-value mono' : 'av-value'}>
                {field.value}
              </span>
            </div>
          ))}
        </div>
      )}
      {hasGps && (
        <div className="av-exif-gps">
          <div className="av-exif-gps-head">
            <span className="av-label">GPS coordinates</span>
            <span className="mono">{coords}</span>
            <CopyButton value={coords} label="coordinates" />
            {altitude != null && (
              <span className="av-note av-exif-alt">Altitude {altitude} m</span>
            )}
          </div>
          <WorldMapDot lat={lat as number} lon={lon as number} />
        </div>
      )}

      <AllExifTags exif={exif} />
    </section>
  )
}

/** Every EXIF tag the parser captured, verbatim — the full forensic record, not
 * just the highlighted fields above. Collapsed by default so it doesn't bury
 * the summary; nothing is hidden once expanded. */
function AllExifTags({ exif }: { exif: Record<string, unknown> }) {
  const raw = exif.raw_exif
  const entries =
    raw && typeof raw === 'object'
      ? Object.entries(raw as Record<string, unknown>)
          .map(([k, v]) => [k, String(v)] as [string, string])
          .sort((a, b) => a[0].localeCompare(b[0]))
      : []
  if (entries.length === 0) return null
  return (
    <details className="av-exif-all">
      <summary>All EXIF tags ({entries.length})</summary>
      <table className="av-exif-table mono">
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k}>
              <td>{k}</td>
              <td>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}
