import { screen } from '@testing-library/react'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { MemoryProfileResponse } from './api'
import { ImageProfilePage } from './ImageProfilePage'
import {
  CASE_ID,
  IMAGE_ID,
  coverageBody,
  image,
  mockImages,
  mockMemory,
  renderMemory,
} from './testing'

const ROUTES = <Route index element={<ImageProfilePage />} />

function profile(
  overrides: Partial<MemoryProfileResponse> = {},
): MemoryProfileResponse {
  return {
    case_id: CASE_ID,
    image_id: IMAGE_ID,
    image: { name: 'WIN10-DESK.mem' },
    analysis_state: 'analysed',
    analysis_state_meaning: 'An image profile was established.',
    record_id: 'profile-1',
    profile_established: true,
    profile: {
      dtb: 0x1ad000,
      dtb_evidence: 'confirmed',
      kernel_base: 0x12a00000,
      kernel_base_evidence: 'scanned',
      architecture: 'X64',
      pointer_size: 8,
      pdb: 'ntkrnlmp.pdb',
      pdb_guid: '1A2B3C4D',
      pdb_age: 1,
      nt_major: 10,
      nt_minor: 0,
      nt_build: 19041,
      nt_build_source: 'kuser_shared_data',
      build_lab: null,
      symbols_state: 'Unverified',
      weakest_evidence: 'scanned',
    },
    weakest_evidence: 'scanned',
    symbols_verified: false,
    symbols_verified_known: true,
    evidence: {
      weakest_evidence: 'scanned',
      weakest_evidence_known: true,
      symbols_verified: false,
      symbols_verified_known: true,
      symbols_state: 'Unverified',
      symbols_provenance: null,
      facts: [
        {
          fact: 'directory_table_base',
          present: true,
          value: 0x1ad000,
          evidence: 'confirmed',
          graded: true,
        },
        {
          fact: 'kernel_base',
          present: true,
          value: 0x12a00000,
          evidence: null,
          graded: false,
        },
        { fact: 'kdbg', present: false, value: null, evidence: null, graded: false },
      ],
      ungraded_facts: 1,
      note: 'Every finding for this image rests on these facts.',
    },
    discovery: null,
    failure: null,
    symbol_dirs_searched: null,
    ...overrides,
  }
}

const COVERAGE = coverageBody([
  { stage: 'processes', status: 'complete', describes: 'The active process list.' },
  { stage: 'network', status: 'did_not_run', describes: 'Network endpoints.' },
])

describe('ImageProfilePage', () => {
  it('states the evidence grade behind each fact the analysis rests on', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('directory table base')).toBeInTheDocument()
    expect(screen.getByLabelText(/evidence confirmed/i)).toBeInTheDocument()
  })

  it('shows what a hibernation header states, alongside its reconstructed image', async () => {
    // A hibernation file is reconstructed into a memory image, but the header
    // still states two facts available from no other artifact: that an image is
    // still in the file, and the moment the machine wrote it. Those belong on
    // the profile next to the analysis of the reconstructed pages.
    mockImages()
    mockMemory(
      `profile/${IMAGE_ID}`,
      profile({
        image: {
          name: 'hiberfil.sys',
          image_format: 'windows_hibernation',
          decode_failed: true,
          hibernation: {
            header_recognised: true,
            signature: 'wake',
            state: 'resumed',
            state_detail:
              'the machine resumed from this image; the pages are normally still present',
            may_hold_an_image: true,
            page_size: 4096,
            system_time_filetime: 132000000000000000,
            pages_stored: 512000,
            first_table_page: 17,
          },
        },
      }),
    )
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('Hibernation file')).toBeInTheDocument()
    expect(screen.getByText('resumed')).toBeInTheDocument()
    expect(screen.getByText('2019-04-17 18:40:00Z')).toBeInTheDocument()
    expect(screen.getByText('512000')).toBeInTheDocument()
    expect(
      screen.getByText(/decompressed .* and reconstructed/i),
    ).toBeInTheDocument()
  })

  it('says so when the bytes are not a hibernation header after all', async () => {
    // The examiner declared the file as hibernation and the file disagrees.
    // That is a finding about the declaration, not a blank panel.
    mockImages()
    mockMemory(
      `profile/${IMAGE_ID}`,
      profile({
        image: {
          name: 'not-really.sys',
          hibernation: {
            header_recognised: false,
            bytes_read: 512,
            detail:
              'the first bytes are not a hibernation header. The declaration is not borne out by the file.',
          },
        },
      }),
    )
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/These bytes are not a hibernation header/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/not borne out by the file/i),
    ).toBeInTheDocument()
    // And no header-facts table: a row of "not stated" under a heading that
    // says these are the facts the header states reads as a file that was read
    // and found empty, when nothing read it as a hibernation image at all.
    expect(screen.queryByText('page size')).not.toBeInTheDocument()
    expect(screen.queryByText('still holds an image')).not.toBeInTheDocument()
    expect(
      screen.queryByText(/These are the facts the header states/i),
    ).not.toBeInTheDocument()
  })

  it('draws no hibernation panel for a capture that is not one', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await screen.findByText('directory table base')
    expect(screen.queryByText('Hibernation file')).not.toBeInTheDocument()
  })

  it('marks a fact that is present but ungraded as not stated, never as a pass', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByLabelText('evidence grade not stated'),
    ).toBeInTheDocument()
    expect(screen.getByText(/Ungraded facts: 1/)).toBeInTheDocument()
  })

  it('says a fact the analysis never established was not established', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('not established')).toBeInTheDocument()
  })

  it('says an unverified symbol table proved nothing', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/nothing proved it either/i),
    ).toBeInTheDocument()
  })

  it('lists which stages ran and which did not, so an empty lens can be interpreted', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('did not run')).toBeInTheDocument()
    expect(screen.getByText('complete')).toBeInTheDocument()
  })

  it('says the container did not declare completeness rather than implying it did', async () => {
    mockImages([
      image({ content_complete: null, content_complete_known: false }),
    ])
    mockMemory(`profile/${IMAGE_ID}`, profile())
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/That is not the same as complete/i),
    ).toBeInTheDocument()
  })

  it('names the symbols to fetch when no symbol table matched, instead of an empty table', async () => {
    mockImages([image({ analysis_state: 'discovery_failed' })])
    mockMemory(
      `profile/${IMAGE_ID}`,
      profile({
        profile_established: false,
        profile: null,
        evidence: null,
        failure:
          'no symbol file matches the kernel: ntkrnlmp.pdb GUID 1A2B3C4D5E6F70819293A4B5C6D7E8F9 age 1. 0 of 4 candidate file(s) under 2 directories were identified',
        symbol_dirs_searched: ['/opt/seance/symbols', '/home/examiner/symbols'],
      }),
    )
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/Structured analysis is not available/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText('1A2B3C4D5E6F70819293A4B5C6D7E8F9'),
    ).toBeInTheDocument()
    expect(screen.getByText('/opt/seance/symbols')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Search' })).toHaveAttribute(
      'href',
      `/cases/${CASE_ID}/search`,
    )
  })

  it('says a discovery failure that names no symbol identity has none to offer', async () => {
    mockImages([image({ analysis_state: 'discovery_failed' })])
    mockMemory(
      `profile/${IMAGE_ID}`,
      profile({
        profile_established: false,
        profile: null,
        evidence: null,
        failure: 'no usable directory table base was found',
        symbol_dirs_searched: [],
      }),
    )
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/does not name a symbol identity/i),
    ).toBeInTheDocument()
  })

  it('says a load failure is a load failure, not a capture that could not be profiled', async () => {
    mockImages()
    mockMemory(`profile/${IMAGE_ID}`, { error: { code: 'X', message: 'y' } }, 500)
    mockMemory('coverage', COVERAGE)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/The capture profile could not be loaded/i),
    ).toBeInTheDocument()
  })
})
