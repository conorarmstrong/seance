import '@testing-library/jest-dom/vitest'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { server } from './server'

// A note for the next person who sees `expect(x).toBeInstanceOf(Blob)` fail on
// a value that is obviously a Blob.
//
// jsdom provides no `fetch`, so msw serves through undici, and
// `response.blob()` returns Node's `buffer.Blob`. jsdom installs a *different*
// class as the global `Blob`. Both are Blobs; `instanceof` is false between
// them. In a browser there is only one, which is why this only bites in tests.
//
// Do not "fix" it by assigning Node's Blob over the global: jsdom's own APIs
// type-check their arguments against jsdom's class, so `FileReader.readAsText`
// then rejects the very value you just made global, and user-event's clipboard
// path breaks. That was tried; it turned one failing test into two.
//
// Assert what the value does — its bytes, size and type — rather than which
// realm minted it. See `thumbnailFetch.test.ts`.

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
