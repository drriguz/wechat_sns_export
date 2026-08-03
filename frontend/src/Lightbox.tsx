import { useEffect } from 'react'
import type { MediaItem } from './types'
import { mediaUrl } from './api'

interface Props {
  media: MediaItem
  total: number
  index: number
  onClose: () => void
  onPrev: () => void
  onNext: () => void
}

export default function Lightbox({ media, total, index, onClose, onPrev, onNext }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'ArrowLeft') onPrev()
      if (e.key === 'ArrowRight') onNext()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, onPrev, onNext])

  const isVideo = /\.(mp4|mov|webm)$/i.test(media.file)
  const url = mediaUrl(media.file || media.thumb_file)

  return (
    <div
      className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black/95"
      onClick={onClose}
    >
      {isVideo ? (
        <video src={url} className="max-h-[85vh] max-w-[92vw]" controls autoPlay />
      ) : (
        <img src={url} alt="" className="max-h-[85vh] max-w-[92vw] object-contain" />
      )}
      <div className="absolute top-4 right-4 flex items-center gap-3">
        {total > 1 && (
          <span className="text-sm text-white/70">
            {index + 1} / {total}
          </span>
        )}
        <button
          type="button"
          onClick={onClose}
          className="rounded-full bg-white/15 px-3 py-1.5 text-sm text-white hover:bg-white/25"
        >
          关闭 ✕
        </button>
      </div>
      {total > 1 && (
        <>
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); onPrev() }}
            className="absolute left-3 top-1/2 -translate-y-1/2 rounded-full bg-white/15 px-3 py-2 text-white hover:bg-white/25"
          >
            ‹
          </button>
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); onNext() }}
            className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full bg-white/15 px-3 py-2 text-white hover:bg-white/25"
          >
            ›
          </button>
        </>
      )}
    </div>
  )
}
