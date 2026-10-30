import { useEffect, useRef, useState } from 'react'

/**
 * One-shot in-view detection via IntersectionObserver. Returns a ref to attach
 * to an element and a boolean that flips true (and stays true) once the element
 * first scrolls near the viewport. Used to lazily fetch gallery thumbnails only
 * for cells the examiner actually reaches.
 *
 * When IntersectionObserver is unavailable (older/test environments without a
 * mock) the element is treated as immediately in view so content still loads.
 */
export function useInView<T extends Element>(rootMargin = '300px') {
  const ref = useRef<T | null>(null)
  const [inView, setInView] = useState(false)

  useEffect(() => {
    if (inView) return
    const el = ref.current
    if (!el) return
    if (typeof IntersectionObserver === 'undefined') {
      setInView(true)
      return
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setInView(true)
            observer.disconnect()
            return
          }
        }
      },
      { rootMargin },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [inView, rootMargin])

  return { ref, inView }
}
