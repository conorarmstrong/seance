import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { useEntityScopedState } from './useEntityScopedState'

describe('useEntityScopedState', () => {
  it('keeps a value while the entity it was set under is still on screen', () => {
    const { result } = renderHook(() =>
      useEntityScopedState<string | null>('case-1', null),
    )

    act(() => result.current[1]('hash-set-a'))
    expect(result.current[0]).toBe('hash-set-a')
  })

  it('reads back as the initial value the moment the entity changes', () => {
    // This is the whole point: the value must already be gone in the FIRST
    // render under the new entity. Resetting in an effect leaves one render in
    // which queries and mutations are configured with case A's id under case
    // B's route, which is enough to send a request to the wrong case.
    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) =>
        useEntityScopedState<string | null>(scope, null),
      { initialProps: { scope: 'case-1' } },
    )

    act(() => result.current[1]('hash-set-a'))
    expect(result.current[0]).toBe('hash-set-a')

    rerender({ scope: 'case-2' })
    expect(result.current[0]).toBeNull()
  })

  it('does not resurrect the previous entity value when the entity comes back', () => {
    // A stale selection returning on a back-navigation is the same defect
    // arriving late: the examiner did not re-make that choice under this case.
    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) =>
        useEntityScopedState<string | null>(scope, null),
      { initialProps: { scope: 'case-1' } },
    )

    act(() => result.current[1]('hash-set-a'))
    rerender({ scope: 'case-2' })
    rerender({ scope: 'case-1' })

    expect(result.current[0]).toBeNull()
  })

  it('gives the updater form the current entity value, not the previous one', () => {
    // A counter or toggle must not continue from the other entity's number: a
    // page cap of 8 carried across would keep case B fetching pages case A's
    // "load more" clicks asked for.
    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) => useEntityScopedState(scope, 1),
      { initialProps: { scope: 'case-1' } },
    )

    act(() => result.current[1]((previous) => previous + 4))
    expect(result.current[0]).toBe(5)

    rerender({ scope: 'case-2' })
    act(() => result.current[1]((previous) => previous + 1))
    expect(result.current[0]).toBe(2)
  })

  it('keeps one setter identity per entity', () => {
    // Memoized rows take these setters as props — the timeline hands
    // `setSelectedIds` to every selection checkbox. A new function on each
    // render would defeat that memoization on tables of hundreds of rows.
    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) =>
        useEntityScopedState<string | null>(scope, null),
      { initialProps: { scope: 'case-1' } },
    )
    const first = result.current[1]

    rerender({ scope: 'case-1' })
    expect(result.current[1]).toBe(first)

    rerender({ scope: 'case-2' })
    expect(result.current[1]).not.toBe(first)
  })

  it('sends a setter captured under the previous entity back to that entity', () => {
    // An async handler that settles after the examiner has switched cases must
    // deposit its value where nothing reads it, not into the case now on
    // screen. That is why the setter is bound to its scope rather than reading
    // the current one.
    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) =>
        useEntityScopedState<string | null>(scope, null),
      { initialProps: { scope: 'case-1' } },
    )
    const staleSetter = result.current[1]

    rerender({ scope: 'case-2' })
    act(() => staleSetter('from-case-1'))

    expect(result.current[0]).toBeNull()
  })

  it('keeps writes made under the new entity', () => {
    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) =>
        useEntityScopedState<string | null>(scope, null),
      { initialProps: { scope: 'case-1' } },
    )

    act(() => result.current[1]('hash-set-a'))
    rerender({ scope: 'case-2' })
    act(() => result.current[1]('hash-set-b'))

    expect(result.current[0]).toBe('hash-set-b')
  })
})
