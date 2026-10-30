// The tab's one connection to /api/v1/events, and the fan-out that lets every
// watcher in the app share it.
//
// Browsers cap concurrent HTTP/1.1 connections per origin at about six, and an
// open EventSource holds one for as long as it is subscribed. When each watcher
// opened its own, an examiner with three case tabs had already spent the budget
// on duplicates of the same broadcast, and the next tab's PRIMARY processing
// stream never connected at all: its onerror looped through backoff forever
// while the case shell showed a run state nothing was updating. One connection
// per tab, as many subscribers as the UI needs.
//
// This module owns the socket and nothing else. It does not know what an event
// means, which case it belongs to, or what the app should do about it — that is
// the reducer's job in `processing.ts`. What it does own is the one thing every
// subscriber has to be told and cannot work out for itself: whether the stream
// is currently up, and whether it has been re-established since they last
// heard from it. A broadcast with no replay means a reconnect is also an
// admission that events were missed, and a subscriber that is not told cannot
// know to go and reconcile.

/** Reconnect backoff schedule in milliseconds; the last entry is the cap. */
const BACKOFF_MS = [1000, 2000, 5000, 10000]

const STREAM_URL = '/api/v1/events'

export type ConnectionStatus = 'live' | 'reconnecting'

export interface SseConnection {
  status: ConnectionStatus
  /** Epoch ms at which the current outage began; null while connected. */
  downSince: number | null
  /**
   * Counts successful opens of the shared socket.
   *
   * A subscriber that sees this advance knows the connection it was listening
   * to was replaced, and therefore that anything broadcast in between is gone
   * — the server keeps no replay. It is the trigger to re-sync from the API
   * rather than to carry the last frame forward.
   */
  generation: number
}

type EventHandler = (event: MessageEvent) => void
type ConnectionHandler = (connection: SseConnection) => void

const eventHandlers = new Map<string, Set<EventHandler>>()
// One stable forwarder per event name, so listeners can be attached to a
// replacement socket and detached from a dying one by identity.
const forwarders = new Map<string, EventHandler>()
const connectionHandlers = new Set<ConnectionHandler>()

let source: EventSource | null = null
let retryTimer: ReturnType<typeof setTimeout> | null = null
let attempt = 0

// Optimistic until proven otherwise: before the first open there has been no
// failure to report, and a status bar that announces an outage during the
// first paint of every page load is announcing nothing that happened.
let connection: SseConnection = { status: 'live', downSince: null, generation: 0 }

export function getSseConnection(): SseConnection {
  return connection
}

function publishConnection(next: SseConnection) {
  connection = next
  for (const handler of [...connectionHandlers]) handler(connection)
}

function subscriberCount(): number {
  let total = connectionHandlers.size
  for (const handlers of eventHandlers.values()) total += handlers.size
  return total
}

function forwarderFor(name: string): EventHandler {
  let forwarder = forwarders.get(name)
  if (!forwarder) {
    forwarder = (event: MessageEvent) => {
      // A copy, because a handler may unsubscribe itself while being called.
      for (const handler of [...(eventHandlers.get(name) ?? [])]) handler(event)
    }
    forwarders.set(name, forwarder)
  }
  return forwarder
}

function connect() {
  const opened = new EventSource(STREAM_URL)
  source = opened
  opened.onopen = () => {
    attempt = 0
    publishConnection({
      status: 'live',
      downSince: null,
      generation: connection.generation + 1,
    })
  }
  opened.onerror = () => {
    // EventSource does its own reconnecting, but only for a socket it still
    // considers usable, and it reports nothing about the gap. Closing and
    // redialling on our own schedule is what makes the outage observable.
    opened.close()
    if (source === opened) source = null
    const delay = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)]
    attempt += 1
    if (retryTimer) clearTimeout(retryTimer)
    retryTimer = setTimeout(() => {
      retryTimer = null
      if (subscriberCount() > 0) connect()
    }, delay)
    publishConnection({
      status: 'reconnecting',
      // A flapping link produces a run of failures; the outage started at the
      // first of them, not at the most recent retry.
      downSince: connection.downSince ?? Date.now(),
      generation: connection.generation,
    })
  }
  for (const name of eventHandlers.keys()) {
    opened.addEventListener(name, forwarderFor(name))
  }
}

function ensureConnected() {
  if (source || retryTimer) return
  connect()
}

function releaseIfIdle() {
  if (subscriberCount() > 0) return
  if (retryTimer) {
    clearTimeout(retryTimer)
    retryTimer = null
  }
  source?.close()
  source = null
  attempt = 0
}

/**
 * Receive the named SSE events until the returned function is called.
 *
 * The name is the server's SSE event name (`processing_status`,
 * `module_progress`, …), not the `event_type` discriminant inside the payload.
 */
export function subscribeSseEvent(name: string, handler: EventHandler): () => void {
  let handlers = eventHandlers.get(name)
  if (!handlers) {
    handlers = new Set()
    eventHandlers.set(name, handlers)
    // A name first subscribed while the socket is already open still has to be
    // attached to it, or the subscriber hears nothing until the next reconnect.
    source?.addEventListener(name, forwarderFor(name))
  }
  handlers.add(handler)
  ensureConnected()

  return () => {
    handlers.delete(handler)
    if (handlers.size === 0) {
      eventHandlers.delete(name)
      const forwarder = forwarders.get(name)
      if (forwarder) {
        source?.removeEventListener(name, forwarder)
        forwarders.delete(name)
      }
    }
    releaseIfIdle()
  }
}

/**
 * Follow the state of the shared connection.
 *
 * The handler is called immediately with the current state, so a subscriber
 * that arrives mid-outage learns about it now rather than at the next
 * transition — the difference between a page that says "stream down" on arrival
 * and one that asserts a stale run state until something changes.
 */
export function subscribeSseConnection(handler: ConnectionHandler): () => void {
  connectionHandlers.add(handler)
  ensureConnected()
  handler(connection)

  return () => {
    connectionHandlers.delete(handler)
    releaseIfIdle()
  }
}

/**
 * Drop the socket and every subscription, and forget the connection history.
 *
 * For tests only: the bus is module state, so without this one test's stubbed
 * EventSource and generation counter leak into the next.
 */
export function resetSseBus() {
  if (retryTimer) clearTimeout(retryTimer)
  retryTimer = null
  source?.close()
  source = null
  attempt = 0
  eventHandlers.clear()
  forwarders.clear()
  connectionHandlers.clear()
  connection = { status: 'live', downSince: null, generation: 0 }
}
