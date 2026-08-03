import { useMemo } from 'react'

const AVATAR_COLORS = [
  '#07C160', '#FF9C19', '#FF5D5D', '#5D9CFF', '#B36BFF',
  '#FF6BB3', '#3EC6C6', '#A8C023', '#FF8B5D', '#6B7BFF',
]

function hash(s: string): number {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0
  return Math.abs(h)
}

export default function Avatar({ name, size = 48 }: { name: string; size?: number }) {
  const color = useMemo(
    () => AVATAR_COLORS[hash(name || '?') % AVATAR_COLORS.length],
    [name],
  )
  const ch = (name || '?').trim().charAt(0) || '?'
  return (
    <div
      className="flex shrink-0 select-none items-center justify-center rounded-[6px] text-white"
      style={{
        width: size,
        height: size,
        backgroundColor: color,
        fontSize: size * 0.45,
        fontWeight: 600,
      }}
      aria-hidden
    >
      {ch}
    </div>
  )
}
