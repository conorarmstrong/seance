import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { X } from 'lucide-react'
import './toast.css'

type ToastKind = 'info' | 'success' | 'error'

interface Toast {
  id: number
  kind: ToastKind
  message: string
}

interface ToastApi {
  info: (message: string) => void
  success: (message: string) => void
  error: (message: string) => void
}

const ToastContext = createContext<ToastApi | null>(null)

const DISMISS_MS = 5000
const ERROR_DISMISS_MS = 10000
const DEDUPE_WINDOW_MS = 2000
const MAX_VISIBLE = 5

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(0)
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>())
  const lastPushed = useRef<{
    id: number
    kind: ToastKind
    message: string
    at: number
  } | null>(null)

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer) clearTimeout(timer)
    timers.current.delete(id)
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const now = Date.now()
      const duration = kind === 'error' ? ERROR_DISMISS_MS : DISMISS_MS

      // Identical consecutive message within the window: refresh its
      // timer instead of stacking a duplicate.
      const last = lastPushed.current
      if (
        last &&
        last.kind === kind &&
        last.message === message &&
        now - last.at < DEDUPE_WINDOW_MS &&
        timers.current.has(last.id)
      ) {
        clearTimeout(timers.current.get(last.id))
        timers.current.set(
          last.id,
          setTimeout(() => dismiss(last.id), duration),
        )
        last.at = now
        return
      }

      const id = nextId.current++
      lastPushed.current = { id, kind, message, at: now }
      setToasts((prev) => {
        const next = [...prev, { id, kind, message }]
        while (next.length > MAX_VISIBLE) {
          const dropped = next.shift()
          if (dropped) {
            const timer = timers.current.get(dropped.id)
            if (timer) clearTimeout(timer)
            timers.current.delete(dropped.id)
          }
        }
        return next
      })
      timers.current.set(
        id,
        setTimeout(() => dismiss(id), duration),
      )
    },
    [dismiss],
  )

  const api = useMemo<ToastApi>(
    () => ({
      info: (m) => push('info', m),
      success: (m) => push('success', m),
      error: (m) => push('error', m),
    }),
    [push],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-stack">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast-${t.kind}`}
            role={t.kind === 'error' ? 'alert' : 'status'}
          >
            <span className="toast-message">{t.message}</span>
            <button
              className="toast-dismiss"
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
