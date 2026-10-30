import type { RequestHandler } from 'msw'

// Populated per-test via server.use(); base handlers live here as the
// API client grows.
export const handlers: RequestHandler[] = []
