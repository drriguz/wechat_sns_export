import { useState } from 'react'
import type { Comment, MediaItem, Post } from './types'
import { mediaUrl } from './api'
import Lightbox from './Lightbox'
import { albumTime } from './time'

const isVideo = (m: MediaItem) => /\.(mp4|mov|webm)$/i.test(m.file || m.thumb_file)

function VideoThumb({ m }: { m: MediaItem }) {
  const [broken, setBroken] = useState(false)
  if (broken || !(m.thumb_file || m.file)) {
    // no usable thumbnail (video posts' "thumb" is often a video URL itself)
    return (
      <span className="flex h-full w-full items-center justify-center bg-black/70">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-white/25 text-white">
          <svg viewBox="0 0 24 24" className="ml-0.5 h-4 w-4" fill="currentColor">
            <path d="M8 5.5v13l11-6.5-11-6.5z" />
          </svg>
        </span>
      </span>
    )
  }
  return (
    <span className="relative block h-full w-full">
      <img
        src={mediaUrl(m.thumb_file || m.file)}
        alt=""
        className="h-full w-full object-cover"
        loading="lazy"
        onError={() => setBroken(true)}
      />
      <span className="absolute inset-0 flex items-center justify-center">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-black/40 text-white">
          <svg viewBox="0 0 24 24" className="ml-0.5 h-4 w-4" fill="currentColor">
            <path d="M8 5.5v13l11-6.5-11-6.5z" />
          </svg>
        </span>
      </span>
    </span>
  )
}

/** Fixed-size image box: same dimensions regardless of image count. */
function AlbumMediaBox({ media }: { media: MediaItem[] }) {
  const [active, setActive] = useState<MediaItem | null>(null)
  // skip media without a local file (e.g. video-link covers were never
  // downloadable) — otherwise the box renders a broken image
  const files = media.filter((m) => m.file || m.thumb_file)
  if (files.length === 0) return null
  const n = files.length
  const cols = n === 1 ? 1 : n <= 4 ? 2 : 3
  return (
    <>
      <button
        type="button"
        className="block h-28 w-28 shrink-0 overflow-hidden rounded-[3px] bg-black/5"
        onClick={() => setActive(files[0])}
        title="查看大图"
      >
        {n === 1 ? (
          isVideo(files[0]) ? (
            <VideoThumb m={files[0]} />
          ) : (
            <img
              src={mediaUrl(files[0].thumb_file || files[0].file)}
              alt=""
              className="h-full w-full object-cover"
              loading="lazy"
            />
          )
        ) : (
          <span
            className="grid h-full w-full gap-0.5 p-0.5"
            style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}
          >
            {files.slice(0, 9).map((m, i) => (
              <span key={m.media_id + i} className="relative block overflow-hidden">
                {isVideo(m) && <VideoThumb m={m} />}
                {!isVideo(m) && (
                  <img
                    src={mediaUrl(m.thumb_file || m.file)}
                    alt=""
                    className="h-full w-full object-cover"
                    loading="lazy"
                  />
                )}
              </span>
            ))}
          </span>
        )}
      </button>
      {active && (
        <Lightbox
          media={active}
          total={files.length}
          index={files.indexOf(active)}
          onClose={() => setActive(null)}
          onPrev={() =>
            setActive(files[(files.indexOf(active) - 1 + files.length) % files.length])
          }
          onNext={() => setActive(files[(files.indexOf(active) + 1) % files.length])}
        />
      )}
    </>
  )
}

function LikeBox({ likes }: { likes: Post['likes'] }) {
  if (!likes.length) return null
  return (
    <div className="mt-1.5 flex items-start gap-1 rounded-[3px] bg-[#F7F7F7] px-2 py-1">
      <svg viewBox="0 0 24 24" className="mt-0.5 h-3.5 w-3.5 shrink-0 fill-[#576B95]">
        <path d="M12 21s-7.5-4.7-10-9.3C.4 8.6 2.4 5 5.8 5c2 0 3.3 1.1 4.2 2.4l2 2.9 2-2.9C15 6.1 16.2 5 18.2 5c3.4 0 5.4 3.6 3.8 6.7C19.5 16.3 12 21 12 21z" />
      </svg>
      <p className="text-[12px] leading-4 text-[#576B95]">
        {likes.map((l, i) => (
          <span key={l.comment_id || i}>
            {i > 0 && '，'}
            <span className="font-medium">{l.nickname || l.username}</span>
          </span>
        ))}
      </p>
    </div>
  )
}

function CommentBox({ comments }: { comments: Comment[] }) {
  if (!comments.length) return null
  return (
    <div className="mt-0.5 rounded-[3px] bg-[#F7F7F7] px-2 py-1">
      {comments.map((c, i) => (
        <p key={c.comment_id || i} className="break-all text-[12px] leading-5">
          <span className="font-medium text-[#576B95]">{c.nickname || c.username}</span>
          {c.to_nickname && c.to_username && (
            <>
              <span className="text-black/40"> 回复 </span>
              <span className="font-medium text-[#576B95]">{c.to_nickname}</span>
            </>
          )}
          <span className="text-black/40">: </span>
          <span className="text-[#333]">{c.content}</span>
        </p>
      ))}
    </div>
  )
}

function LinkCard({ post }: { post: Post }) {
  const link = post.link
  // only shared-link posts (types 3/5) render a link card; other posts may
  // carry a stray contentUrl (e.g. WeChat support placeholder) — ignore it
  if (!link) return null
  const url = post.link_url
  if (!url) return null
  let domain = ''
  try {
    domain = new URL(url).hostname
  } catch {
    domain = url
  }
  // prefer the locally decrypted media file as the cover (always reliable);
  // fall back to the CDN-fetched link thumbnail
  const localFile = post.media.find((m) => m.file || m.thumb_file)
  const coverSrc = localFile
    ? mediaUrl(localFile.thumb_file || localFile.file)
    : link?.thumb_url
      ? `/media/link-card/${post.id}`
      : ''
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className="mt-1.5 flex items-center gap-2 rounded-[3px] border border-[#E5E5E5] bg-[#FAFAFA] px-2 py-1.5 no-underline transition-colors hover:border-[#07C160]"
    >
      {coverSrc && (
        <span className="block h-11 w-11 shrink-0 overflow-hidden rounded-[3px] bg-black/5">
          <img
            src={coverSrc}
            alt=""
            className="h-full w-full object-cover"
            loading="lazy"
            onError={(e) => {
              ;(e.target as HTMLImageElement).style.display = 'none'
            }}
          />
        </span>
      )}
      <span className="min-w-0 flex-1">
        {link?.title && (
          <span className="block truncate text-[13px] font-medium text-[#333]">
            {link.title}
          </span>
        )}
        {link?.description && (
          <span className="block truncate text-[12px] text-[#9A9A9A]">
            {link.description}
          </span>
        )}
        <span className="block truncate text-[11px] text-[#9A9A9A]">
          {link?.source ? `来自 ${link.source}` : domain}
        </span>
      </span>
      <span className="shrink-0 text-[12px] text-[#07C160]">›</span>
    </a>
  )
}

function FinderCard({ post }: { post: Post }) {
  const f = post.finder
  if (!f || !f.nickname) return null
  return (
    <a
      href={f.video_url || '#'}
      target="_blank"
      rel="noreferrer"
      className="mt-1.5 flex items-center gap-2 rounded-[3px] border border-[#E5E5E5] bg-[#FAFAFA] px-2 py-1.5 no-underline transition-colors hover:border-[#07C160]"
    >
      <span className="block h-11 w-11 shrink-0 overflow-hidden rounded-[3px] bg-black/5">
        <img
          src={`/media/finder-thumb/${post.id}`}
          alt=""
          className="h-full w-full object-cover"
          loading="lazy"
          onError={(e) => {
            ;(e.target as HTMLImageElement).style.display = 'none'
          }}
        />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] font-medium text-[#333]">
          {f.nickname}&apos;s Activity
        </span>
        {f.desc && (
          <span className="block truncate text-[12px] text-[#9A9A9A]">
            {f.desc}
          </span>
        )}
        <span className="block truncate text-[11px] text-[#9A9A9A]">
          来自视频号
        </span>
      </span>
      <span className="shrink-0 text-[12px] text-[#07C160]">›</span>
    </a>
  )
}

export default function PostCard({ post }: { post: Post }) {
  const [expanded, setExpanded] = useState(false)
  const t = albumTime(post.create_time)
  const text = post.content_desc || ''
  const longText = text.length > 60

  return (
    <article className="flex gap-3 border-b border-[#EFEFEF] px-4 py-4">
      {/* date */}
      <div className="w-14 shrink-0 select-none">
        <p className="text-[12px] leading-4 text-[#9A9A9A]">{t.year}</p>
        <p className="text-[16px] leading-6 font-semibold text-[#333]">{t.monthDay}</p>
      </div>

      {/* fixed-size image box (shared-link posts render the cover inside the
          link card instead, so no separate box) */}
      {!post.link && <AlbumMediaBox media={post.media} />}

      {/* content on the right */}
      <div className="min-w-0 flex-1">
        {text && (
          <div>
            <p
              className={`whitespace-pre-wrap break-all text-[14px] leading-[1.5] text-[#333] ${
                longText && !expanded ? 'line-clamp-3' : ''
              }`}
            >
              {text}
            </p>
            {longText && (
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                className="mt-0.5 text-[12px] text-[#576B95]"
              >
                {expanded ? '收起' : '全文'}
              </button>
            )}
          </div>
        )}

        <LinkCard post={post} />

        <FinderCard post={post} />

        {post.location?.poi_name && (
          <p className="mt-1 flex items-center gap-0.5 text-[11px] text-[#9A9A9A]">
            📍{post.location.poi_name}
          </p>
        )}

        {(post.likes.length > 0 || post.comments.length > 0) && (
          <div className="mt-1">
            <LikeBox likes={post.likes} />
            <CommentBox comments={post.comments} />
          </div>
        )}
      </div>
    </article>
  )
}
