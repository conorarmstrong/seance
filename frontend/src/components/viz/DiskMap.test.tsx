import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { DiskMapResponse } from './api'
import { DiskMap } from './DiskMap'

const GIB = 1024 ** 3

function renderMap(data: DiskMapResponse) {
  render(
    <MemoryRouter>
      <DiskMap caseId="case-1" data={data} />
    </MemoryRouter>,
  )
}

describe('DiskMap', () => {
  it('renders regions, hatch pattern, and the scale ruler', () => {
    renderMap({
      total_bytes: 100 * GIB,
      regions: [
        {
          artifact_id: 'p1',
          artifact_type: 'Partition',
          parent_id: null,
          offset_bytes: 0,
          size_bytes: 60 * GIB,
          name: 'Partition 1',
          scheme: 'gpt',
          fs_type: null,
        },
        {
          artifact_id: 'fs1',
          artifact_type: 'FileSystem',
          parent_id: 'p1',
          offset_bytes: 0,
          size_bytes: 60 * GIB,
          name: 'NTFS volume',
          scheme: null,
          fs_type: 'ntfs',
        },
        {
          artifact_id: 'u1',
          artifact_type: 'UnallocatedSpace',
          parent_id: null,
          offset_bytes: 60 * GIB,
          size_bytes: 40 * GIB,
          name: 'Unallocated 1',
          scheme: null,
          fs_type: null,
        },
      ],
    })

    const strip = screen.getByRole('group', { name: 'Disk layout map' })
    expect(strip.querySelector('pattern')).not.toBeNull()

    // Partition and its filesystem overlay are separate click targets
    expect(
      screen.getByRole('button', { name: 'Partition 1 — partition' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'NTFS volume — file system' }),
    ).toBeInTheDocument()
    const unalloc = screen.getByRole('button', {
      name: 'Unallocated 1 — unallocated',
    })
    // Unallocated space is hatched via the pattern fill
    expect(unalloc.querySelector('rect')?.getAttribute('fill')).toMatch(/^url\(#/)

    // FS label rides the partition block
    expect(screen.getByText('NTFS')).toBeInTheDocument()

    // Ruler: zero and total at the ends
    expect(screen.getByText('0')).toBeInTheDocument()
    expect(screen.getByText('100.0 GiB')).toBeInTheDocument()
  })

  it('gives sub-1% regions a minimum width with an overflow indicator', () => {
    renderMap({
      total_bytes: 1000 * GIB,
      regions: [
        {
          artifact_id: 'p1',
          artifact_type: 'Partition',
          parent_id: null,
          offset_bytes: 0,
          size_bytes: 0.5 * GIB, // 0.05% of the disk
          name: 'EFI',
          scheme: 'gpt',
          fs_type: null,
        },
        {
          artifact_id: 'p2',
          artifact_type: 'Partition',
          parent_id: null,
          offset_bytes: 0.5 * GIB,
          size_bytes: 999.5 * GIB,
          name: 'Main',
          scheme: 'gpt',
          fs_type: null,
        },
      ],
    })

    const tiny = screen.getByRole('button', { name: 'EFI — partition' })
    const rect = tiny.querySelector('rect')
    expect(Number(rect?.getAttribute('width'))).toBeGreaterThanOrEqual(8)
    expect(screen.getByTestId('dm-enlarged')).toBeInTheDocument()
  })

  it('shows an empty note when there are no regions', () => {
    renderMap({ total_bytes: 0, regions: [] })
    expect(
      screen.getByText('No layout information for this source.'),
    ).toBeInTheDocument()
  })
})
