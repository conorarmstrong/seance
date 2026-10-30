import { describe, expect, it } from 'vitest'
import type { BookmarkCategory } from '../../api/types'
import { folderPath, folderTree } from './folderTree'

function cat(id: string, name: string, parent_id: string | null = null): BookmarkCategory {
  return { id, case_id: 'c', name, color: '#fff', created_at: 0, parent_id }
}

describe('folderTree', () => {
  it('lists folders depth-first, each under its parent, siblings by name', () => {
    const rows = folderTree([
      cat('3', 'Suspect', '1'),
      cat('1', 'Emails'),
      cat('2', 'Chats'),
      cat('4', 'Draft', '3'),
    ])
    expect(rows.map((r) => [r.category.name, r.depth])).toEqual([
      ['Chats', 0],
      ['Emails', 0],
      ['Suspect', 1],
      ['Draft', 2],
    ])
  })

  it('shows a folder whose parent is missing at the top level rather than hiding it', () => {
    // A folder is never lost by a damaged or filtered listing.
    const rows = folderTree([cat('9', 'Orphan', 'gone'), cat('1', 'Root')])
    expect(rows.map((r) => [r.category.name, r.depth])).toEqual([
      ['Orphan', 0],
      ['Root', 0],
    ])
  })

  it('does not loop on a cycle in the data: every folder appears once', () => {
    const rows = folderTree([cat('a', 'A', 'b'), cat('b', 'B', 'a')])
    expect(rows.map((r) => r.category.id).sort()).toEqual(['a', 'b'])
  })
})

describe('folderPath', () => {
  it('names a folder by its whole path', () => {
    const all = [cat('1', 'Emails'), cat('2', 'Suspect', '1'), cat('3', 'Draft', '2')]
    expect(folderPath(all, '3')).toBe('Emails / Suspect / Draft')
    expect(folderPath(all, '1')).toBe('Emails')
    expect(folderPath(all, 'nope')).toBe('')
  })
})
