import { useLayoutEffect, useRef, useState } from 'react'

/**
 * Measures the pixel width of a container so SVG/canvas charts can lay
 * out in real pixels (crisp hairlines, undistorted text). Falls back to
 * a fixed width where layout is unavailable (jsdom).
 */
export function useMeasuredWidth<T extends HTMLElement>(fallback = 800) {
  const ref = useRef<T | null>(null)
  const [width, setWidth] = useState(fallback)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const update = () => {
      const w = el.clientWidth
      if (w > 0) setWidth(w)
    }
    update()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(update)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  return { ref, width }
}
