export function formatTime(ts: number): string {
  if (!ts) return ''
  const diff = Math.floor(Date.now() / 1000) - ts
  const MIN = 60, HOUR = 3600, DAY = 86400
  if (diff < MIN) return '刚刚'
  if (diff < HOUR) return `${Math.floor(diff / MIN)}分钟前`
  if (diff < DAY) return `${Math.floor(diff / HOUR)}小时前`
  if (diff < 2 * DAY) return '昨天'
  if (diff < 7 * DAY) return `${Math.floor(diff / DAY)}天前`
  const d = new Date(ts * 1000)
  const now = new Date()
  const sameYear = d.getFullYear() === now.getFullYear()
  return sameYear
    ? `${d.getMonth() + 1}月${d.getDate()}日`
    : `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`
}

/** Album-style date: year and month/day split into two lines. */
export function albumTime(ts: number): { year: string; monthDay: string } {
  if (!ts) return { year: '', monthDay: '' }
  const d = new Date(ts * 1000)
  const now = new Date()
  const year = d.getFullYear() === now.getFullYear() ? '' : `${d.getFullYear()}年`
  return { year, monthDay: `${d.getMonth() + 1}月${d.getDate()}日` }
}
