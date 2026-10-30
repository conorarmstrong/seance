export type CommKind = 'self' | 'contact' | 'email'

export interface CommNode {
  id: string
  label: string
  kind: CommKind
  weight: number
}

export interface CommEdge {
  source: string
  target: string
  weight: number
}

export interface CommunicationGraph {
  nodes: CommNode[]
  edges: CommEdge[]
  truncated: boolean
  total_participants: number
}
