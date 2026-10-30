/**
 * The end of a calendar day in the examiner's own time zone, as Unix seconds.
 * A due date names a day, and "due 31 January" means the examiner still has
 * all of it, so the target is the last second of that day — not midnight at
 * its start, which would call the work overdue while the day is still running.
 */
export function endOfLocalDay(yyyyMmDd: string): number {
  return Math.floor(new Date(`${yyyyMmDd}T23:59:59`).getTime() / 1000);
}
