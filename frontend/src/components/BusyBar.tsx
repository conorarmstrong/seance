import { useIsFetching, useIsMutating } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

const DEBOUNCE_MS = 300

/**
 * Fixed 2px indeterminate progress bar across the top of the viewport,
 * shown while any react-query fetch or mutation is in flight. Appearance
 * is debounced so quick requests do not flash.
 */
export function BusyBar() {
  const fetching = useIsFetching()
  const mutating = useIsMutating()
  const busy = fetching + mutating > 0
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    if (!busy) {
      setVisible(false)
      return
    }
    const timer = setTimeout(() => setVisible(true), DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [busy])

  if (!visible) return null
  return (
    <div
      className="busy-bar"
      role="progressbar"
      aria-label="Working"
      aria-valuetext="Working"
    />
  )
}
