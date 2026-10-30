import { useMemo } from 'react'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { getMemoryHives, getMemoryServices, type StageEnvelope } from './api'
import { useMemoryContext } from './memoryContext'
import { LensGate } from './LensState'
import { FieldCell, StageTable, type BlobColumn } from './StageTable'
import {
  blobBool,
  blobNumber,
  blobString,
  fieldLeaf,
  hexAddress,
  readNumberField,
  readStageRows,
  readWireText,
  readWireTextOf,
  wireKind,
} from './normalize'

/**
 * Services and registry hives: the two kernel-surface lists an examiner reaches
 * for after the process tree.
 *
 * The hive list carries the fact that has no equivalent on a disk image: a hive
 * with no backing file exists only in RAM. It appears in no disk acquisition at
 * all, so its absence from the disk evidence is expected rather than
 * suspicious, and the row says so instead of leaving the examiner to remember
 * it.
 */

const SERVICE_COLUMNS: BlobColumn[] = [
  {
    id: 'name',
    header: 'service',
    mono: true,
    // Every text field on a service record is a tagged field
    // (`{kind:"known", value}`), because a build that declares no such member
    // and a service whose name would not read are different findings. Read as
    // a plain string they all decoded to null, so the whole services table
    // rendered "not recorded" (same defect as B8-037).
    render: (data) => (
      <FieldCell field={readWireTextOf(data, ['name', 'service_name'])} />
    ),
  },
  {
    id: 'display',
    header: 'display name',
    render: (data) => <FieldCell field={readWireText(data.display_name)} />,
  },
  {
    id: 'state',
    header: 'state',
    render: (data) => blobString(data, 'state') ?? blobString(data, 'status'),
  },
  {
    id: 'start',
    header: 'start type',
    render: (data) => blobString(data, 'start_type') ?? blobString(data, 'start'),
  },
  {
    id: 'binary',
    header: 'binary',
    mono: true,
    render: (data) => (
      <FieldCell field={readWireTextOf(data, ['binary_path', 'binary'])} />
    ),
  },
  {
    id: 'pid',
    header: 'pid',
    mono: true,
    // Tagged too: `not_applicable` for a driver or a stopped service, which is
    // not the same as a service whose pid could not be read.
    render: (data) => {
      const flat = blobNumber(data, 'pid')
      if (flat != null) return String(flat)
      if (data.pid == null) return null
      return <FieldCell field={readNumberField(data.pid)} />
    },
  },
]

/**
 * A hive's name, which the walk sends as `{kind:"path", text, source}` or as
 * `{kind:"no_backing_file"}` — the marker for a hive that exists only in RAM.
 * Read as a plain string it was null for every hive, so the whole list rendered
 * "not recorded" and the volatile badge below could never fire.
 */
function hiveName(data: Record<string, unknown>) {
  return readWireTextOf(data, ['name', 'file_full_path', 'file_name'])
}

/** True when the walk itself said the hive has no file behind it. */
function hiveIsVolatile(data: Record<string, unknown>): boolean {
  if (blobBool(data, 'volatile') === true) return true
  if (wireKind(data.name) === 'no_backing_file') return true
  const name = hiveName(data)
  return name.known && name.value.startsWith('\\REGISTRY\\MACHINE\\HARDWARE')
}

const HIVE_COLUMNS: BlobColumn[] = [
  {
    id: 'name',
    header: 'hive',
    mono: true,
    render: (data) => <FieldCell field={fieldLeaf(hiveName(data))} />,
  },
  {
    id: 'address',
    header: 'address',
    mono: true,
    render: (data) =>
      hexAddress(data, 'address') ?? hexAddress(data, 'hive_offset'),
  },
  {
    id: 'backing',
    header: 'backing file',
    mono: true,
    render: (data) => {
      const name = hiveName(data)
      if (name.known && !hiveIsVolatile(data)) return name.value
      if (hiveIsVolatile(data)) {
        return (
          <span
            className="badge badge-accent"
            title="This hive exists only in RAM and appears in no disk image, so its absence from the disk evidence is expected."
          >
            volatile — RAM only
          </span>
        )
      }
      // Not "no backing file": the name it would have come from could not be
      // read, and that is a hole in the evidence rather than a fact about the
      // hive.
      return <FieldCell field={name} />
    },
  },
]

export function MemorySystemPage() {
  const { caseId, imageId, scopeKey } = useMemoryContext()

  const servicesQuery = useEntityScopedQuery<StageEnvelope>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'services'],
    queryFn: () => getMemoryServices(caseId, imageId),
    retry: false,
  })
  const hivesQuery = useEntityScopedQuery<StageEnvelope>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'hives'],
    queryFn: () => getMemoryHives(caseId, imageId),
    retry: false,
  })

  const serviceRows = useMemo(
    () => readStageRows(servicesQuery.scoped, ['services', 'entries']),
    [servicesQuery.scoped],
  )
  const hiveRows = useMemo(
    () => readStageRows(hivesQuery.scoped, ['hives', 'entries']),
    [hivesQuery.scoped],
  )

  return (
    <div className="mem-system">
      <section className="panel" aria-labelledby="mem-services">
        <h2 className="panel-title" id="mem-services">
          Services
        </h2>
        <LensGate
          label="Services"
          pending={servicesQuery.isPending}
          stale={servicesQuery.stale}
          error={servicesQuery.isError ? servicesQuery.error : undefined}
          envelope={servicesQuery.scoped}
          rowCount={serviceRows.length}
          columns={6}
          emptyTitle="No service record was recovered"
          emptyReason="The service-record scan ran and recovered nothing. A running Windows machine has dozens, so an empty result points at the scan or the symbol table rather than at the machine."
        >
          <StageTable
            rows={serviceRows}
            columns={SERVICE_COLUMNS}
            filter={{ scopeId: `services-${imageId}`, noun: 'service' }}
          />
        </LensGate>
      </section>

      <section className="panel" aria-labelledby="mem-hives">
        <h2 className="panel-title" id="mem-hives">
          Registry hives in memory
        </h2>
        <LensGate
          label="Registry hives"
          pending={hivesQuery.isPending}
          stale={hivesQuery.stale}
          error={hivesQuery.isError ? hivesQuery.error : undefined}
          envelope={hivesQuery.scoped}
          rowCount={hiveRows.length}
          columns={4}
          emptyTitle="No hive was found in kernel memory"
          emptyReason="The hive list was walked and carried no entry. Every running Windows machine has at least SYSTEM and SOFTWARE loaded, so this points at the walk rather than at the machine."
        >
          <StageTable
            rows={hiveRows}
            columns={HIVE_COLUMNS}
            filter={{ scopeId: `hives-${imageId}`, noun: 'hive' }}
          />
        </LensGate>
      </section>
    </div>
  )
}
