import type { BookmarkCategory } from '../../api/types'

/** One folder in display order, with how deep it sits. */
export interface FolderRow {
  category: BookmarkCategory
  depth: number
}

/**
 * The bookmark folders in display order: depth-first, each folder directly
 * under its parent, siblings by name.
 *
 * A folder whose parent is not in the listing is shown at the top level rather
 * than dropped, and a cycle in the data (which the server refuses to create)
 * cannot make the walk loop or hide a folder: every folder appears exactly once.
 */
export function folderTree(categories: BookmarkCategory[]): FolderRow[] {
  const byId = new Map(categories.map((c) => [c.id, c]))
  const children = new Map<string | null, BookmarkCategory[]>()
  for (const c of categories) {
    const parent = c.parent_id && byId.has(c.parent_id) ? c.parent_id : null
    const siblings = children.get(parent) ?? []
    siblings.push(c)
    children.set(parent, siblings)
  }
  for (const siblings of children.values()) {
    siblings.sort((a, b) => a.name.localeCompare(b.name))
  }
  const rows: FolderRow[] = []
  const seen = new Set<string>()
  const walk = (parent: string | null, depth: number) => {
    for (const c of children.get(parent) ?? []) {
      if (seen.has(c.id)) continue
      seen.add(c.id)
      rows.push({ category: c, depth })
      walk(c.id, depth + 1)
    }
  }
  walk(null, 0)
  // Anything a cycle kept from the walk above is still listed, at the top level.
  for (const c of categories) {
    if (!seen.has(c.id)) {
      seen.add(c.id)
      rows.push({ category: c, depth: 0 })
    }
  }
  return rows
}

/** A folder's whole path, `Emails / Suspect / Draft`; empty if it is unknown. */
export function folderPath(categories: BookmarkCategory[], id: string): string {
  const byId = new Map(categories.map((c) => [c.id, c]))
  const names: string[] = []
  const guard = new Set<string>()
  let current = byId.get(id)
  while (current && !guard.has(current.id)) {
    guard.add(current.id)
    names.unshift(current.name)
    current = current.parent_id ? byId.get(current.parent_id) : undefined
  }
  return names.join(' / ')
}
