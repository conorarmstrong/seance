import { Link } from 'react-router-dom'
import type { MemoryImageSummary } from '../memory/api'
import { formatCount } from '../../lib/format'

/**
 * The door from a piece of evidence into the memory analysis of it.
 *
 * Why this exists: the evidence navigator hides `ParsedRecord` children, so an
 * examiner browsing the physical tree — image, partition, filesystem, file —
 * sees the RAM capture as a file and never sees the `MemoryImage` record
 * decoded from it. Before this tab the only route into the analysis was to
 * leave the tree, open the Memory section, and pick the same file out of a
 * dropdown, having already been looking at it.
 *
 * It is a doorway, not a viewer. The Memory section owns seventeen record
 * types across its own lenses; duplicating any of them here would give an
 * examiner two places to read the same finding and two chances for those to
 * disagree. So this states what was decoded, how far the analysis got, and
 * links through — carrying the image id, which is what scopes every lens.
 */
export function MemoryTab({
  caseId,
  image,
}: {
  caseId: string
  /** The capture decoded from the artifact on screen. */
  image: MemoryImageSummary
}) {
  const to = `/cases/${caseId}/memory?image=${encodeURIComponent(image.image_id)}`

  // "Did not say" is not "complete". A container that declared nothing about
  // its own completeness must not render as though it declared success.
  const completeness =
    image.content_complete === true
      ? 'The container declared its content complete'
      : image.content_complete === false
        ? 'The container declared its content INCOMPLETE'
        : 'The container did not state whether its content is complete'

  return (
    <div className="memory-tab">
      <h3>Memory capture</h3>
      <dl className="av-mem-kv">
        <dt>Format</dt>
        <dd>{image.image_format ?? 'not stated'}</dd>
        <dt>Architecture</dt>
        <dd>{image.architecture ?? 'not established'}</dd>
        <dt>Addressable</dt>
        <dd>
          {image.addressable_bytes == null
            ? 'not stated'
            : `${formatCount(image.addressable_bytes)} bytes`}
        </dd>
        <dt>Analysis</dt>
        <dd>{image.analysis_state_meaning ?? image.analysis_state ?? 'unknown'}</dd>
      </dl>

      <p className="av-mem-note">{completeness}.</p>

      {/* A size the container claims but cannot deliver is a finding about the
          acquisition, not a display detail, so it is said here rather than
          only inside the Memory section. */}
      {image.size_mismatch && (
        <p className="av-mem-notice" role="note">
          The container declares a size the file does not match. Some of this
          capture may never have been written.
        </p>
      )}
      {image.decode_failed && (
        <p className="av-mem-notice" role="note">
          This capture could not be decoded. Any absence of processes, network
          endpoints or modules below is a gap in the analysis, not a finding
          about the machine.
        </p>
      )}
      {image.stage_failures > 0 && (
        <p className="av-mem-notice" role="note">
          {formatCount(image.stage_failures)} analysis stage
          {image.stage_failures === 1 ? '' : 's'} could not run. The Memory
          section names each one and why.
        </p>
      )}

      <p>
        <Link className="btn" to={to}>
          Open in Memory analysis
        </Link>
      </p>
      <p className="av-mem-note">
        The Memory section is scoped to this capture. A case holding more than
        one is never merged — each is analysed separately.
      </p>
    </div>
  )
}
