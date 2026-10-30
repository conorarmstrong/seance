/** "FileEntry" -> "File entry". */
export function humanizeArtifactType(type: string): string {
  const spaced = type
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/_/g, ' ')
    .toLowerCase()
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

/** "FileEntry" -> "File entries"; mass nouns stay singular. */
export function humanizeArtifactTypePlural(type: string): string {
  const label = humanizeArtifactType(type)
  if (/(s|data|media|space)$/i.test(label)) return label
  if (/[^aeiou]y$/i.test(label)) return `${label.slice(0, -1)}ies`
  return `${label}s`
}

/**
 * How to name one filesystem region in the evidence-sources panel.
 *
 * An APFS container holds a dozen volumes, and labelling each by its filesystem
 * type alone rendered a dozen identical "Disk usage — APFS" rows: the examiner
 * could not tell Macintosh HD from Preboot, Recovery or VM, even though the
 * volume name was already loaded on the region being labelled (LIVE-018). The
 * name leads; the type is appended only when the name does not already carry
 * it, so an "NTFS volume" is not padded into "NTFS volume (NTFS)".
 */
export function fsUsageLabel(region: {
  name: string | null
  fs_type: string | null
}): string {
  // Both arrive null in real data — an APFS volume region carries no name, and
  // the response type said `string`, so trusting it blanked the whole dashboard
  // with "Cannot read properties of null". A label is decoration; it must never
  // be the thing that takes the page down.
  const type = region.fs_type ? region.fs_type.toUpperCase() : null
  const name = region.name?.trim() ?? ''
  if (!name) return type ?? 'File system'
  if (!type) return name
  return name.toUpperCase().includes(type) ? name : `${name} (${type})`
}
