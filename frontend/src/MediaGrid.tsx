import { useState } from 'react'
import type { MediaItem } from './types'
import { mediaUrl } from './api'
import Lightbox from './Lightbox'

const EXT_VIDEO = ['mp4', 'mov', 'webm']

function isVideo(m: MediaItem): boolean {
  return EXT_VIDEO.some((e) => m.file.toLowerCase().endsWith(e))
}

interface Props {
  media: MediaItem[]
}

export default function MediaGrid({ media }: Props) {
  const [active, setActive] = useState<MediaItem | null>(null)
  if (media.length === 0) return null

  const n = media.length
  // WeChat-style grid: 1 large, 3 across, 9 in 3x3
  const cols = n === 1 ? 1 : 3
  const grid = n === 1 ? 'grid-cols-1' : 'grid-cols-3'
  const gap = n === 1 ? 'gap-0' : 'gap-1.5'

  const size = (): { aspect?: string } => {
    if (n === 1) {
      const m = media[0]
      const w = m.width || 1
      const h = m.height || 1
      return { aspect: `${Math.min(w, 2000)} / ${Math.min(h, 2000)}` }
    }
    return {}
  }

  return (
    <>
      <div className={`mt-2 grid w-full max-w-[320px] ${grid} ${gap}`}>
        {media.map((m, i) => {
          const s = size()
          return (
            <button
              key={m.media_id + i}
              type="button"
              className="group relative block overflow-hidden bg-black/5"
              style={s.aspect ? { aspectRatio: s.aspect } : { aspectRatio: '1 / 1', width: cols === 1 ? undefined : '100%' }}
              onClick={() => setActive(m)}
              title="查看大图"
            >
              {isVideo(m) ? (
                <>
                  <img
                    src={mediaUrl(m.thumb_file || m.file)}
                    alt=""
                    className="h-full w-full object-cover"
                    loading="lazy"
                  />
                  <span className="absolute inset-0 flex items-center justify-center">
                    <span className="flex h-10 w-10 items-center justify-center rounded-full bg-black/40 text-white">
                      <svg viewBox="0 0 24 24" className="ml-0.5 h-6 w-6" fill="currentColor">
                        <path d="M8 5.5v13l11-6.5-11-6.5z" />
                      </svg>
                    </span>
                  </span>
                </>
              ) : (
                <img
                  src={mediaUrl(m.thumb_file || m.file)}
                  alt=""
                  className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-105"
                  loading="lazy"
                />
              )}
            </button>
          )
        })}
      </div>
      {active && (
        <Lightbox
          media={active}
          total={media.length}
          index={media.indexOf(active)}
          onClose={() => setActive(null)}
          onPrev={() =>
            setActive(media[(media.indexOf(active) - 1 + media.length) % media.length])
          }
          onNext={() => setActive(media[(media.indexOf(active) + 1) % media.length])}
        />
      )}
    </>
  )
}
