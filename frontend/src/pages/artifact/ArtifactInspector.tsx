import { useState } from 'react'
import { PanelRightClose } from 'lucide-react'
import type { Artifact } from '../../api/types'
import { hasByteContent, type PreviewKind } from './lib'
import { KeychainRevealPanel, keychainRevealFor } from './KeychainRevealPanel'
import { ExifSection } from './MediaSection'
import { OverviewTab, PropertiesTab } from './MetadataTabs'
import { OwnershipSection } from './OwnershipSection'
import { PhysicalLocationSection } from './PhysicalLocationSection'
import { ReadUnlockPanel, readUnlockableFor } from './ReadUnlockPanel'
import { SqliteHint } from './SqliteHint'
import { VolumeReadUnlockPanel } from './VolumeReadUnlockPanel'

/**
 * The persistent right-hand Inspector: an artifact's metadata shown *beside* the
 * viewer rather than in a mutually-exclusive tab. Composes the existing metadata
 * renderers (overview cards + timestamps, EXIF/GPS for images, the SQLite
 * summary) and puts the full key/value dump behind a toggle so the common facts
 * stay glanceable. Empty sections collapse via `.av-insp-sec:empty`.
 */
export function ArtifactInspector({
  caseId,
  artifact,
  previewKind,
  onCollapse,
}: {
  caseId: string
  artifact: Artifact
  previewKind: PreviewKind | null
  onCollapse: () => void
}) {
  const [showProps, setShowProps] = useState(false)
  const propCount = Object.keys(artifact.metadata).length
  return (
    <aside className="av-inspector-pane" aria-label="Properties">
      <div className="av-insp-head">
        <h2>Inspector</h2>
        <button
          type="button"
          className="icon-btn"
          aria-label="Hide inspector"
          title="Hide inspector"
          onClick={onCollapse}
        >
          <PanelRightClose size={15} />
        </button>
      </div>
      <div className="av-insp-body">
        <div className="av-insp-sec">
          <OverviewTab artifact={artifact} caseId={caseId} />
        </div>
        {readUnlockableFor(artifact) && (
          <div className="av-insp-sec">
            <ReadUnlockPanel caseId={caseId} artifact={artifact} />
          </div>
        )}
        {/* An iOS backup keychain item's withheld secret: the audited reveal (HUNT-111). */}
        {keychainRevealFor(artifact) && (
          <div className="av-insp-sec">
            <KeychainRevealPanel caseId={caseId} artifact={artifact} />
          </div>
        )}
        {/* Collapses (:empty) unless the artifact is on a decrypted volume. */}
        <div className="av-insp-sec">
          <VolumeReadUnlockPanel caseId={caseId} artifact={artifact} />
        </div>
        {hasByteContent(artifact.artifact_type) && (
          <div className="av-insp-sec">
            <PhysicalLocationSection caseId={caseId} artifactId={artifact.id} />
          </div>
        )}
        {artifact.artifact_type === 'FileEntry' && (
          <div className="av-insp-sec">
            <OwnershipSection caseId={caseId} artifact={artifact} />
          </div>
        )}
        {previewKind === 'image' && (
          <div className="av-insp-sec">
            <ExifSection caseId={caseId} artifactId={artifact.id} />
          </div>
        )}
        <div className="av-insp-sec">
          <SqliteHint
            caseId={caseId}
            artifactId={artifact.id}
            artifactType={artifact.artifact_type}
          />
        </div>
        <div className="av-insp-sec av-insp-props">
          <button
            type="button"
            className="av-insp-props-toggle"
            aria-expanded={showProps}
            onClick={() => setShowProps((v) => !v)}
          >
            {showProps ? 'Hide' : 'Show'} all properties ({propCount})
          </button>
          {showProps && <PropertiesTab metadata={artifact.metadata} />}
        </div>
      </div>
    </aside>
  )
}
