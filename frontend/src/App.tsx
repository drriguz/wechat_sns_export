import { useEffect, useRef, useState } from 'react'
import type { Post } from './types'
import { fetchPosts } from './api'
import PostCard from './PostCard'

const PAGE_SIZE = 10

export default function App() {
  const [posts, setPosts] = useState<Post[]>([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [hasMore, setHasMore] = useState(true)
  const sentinelRef = useRef<HTMLDivElement>(null)
  const busyRef = useRef(false)

  // reset + first page when the search term changes
  useEffect(() => {
    busyRef.current = true
    setLoading(true)
    setError('')
    fetchPosts(1, PAGE_SIZE, search)
      .then((d) => {
        setPosts(d.items)
        setTotal(d.total)
        setPage(d.page)
        setHasMore(d.page < d.pages)
      })
      .catch((e) => setError(String(e)))
      .finally(() => {
        setLoading(false)
        busyRef.current = false
      })
  }, [search])

  // load next page when the sentinel enters the viewport
  useEffect(() => {
    const el = sentinelRef.current
    if (!el) return
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && !busyRef.current && hasMore) {
          busyRef.current = true
          setLoading(true)
          const next = page + 1
          fetchPosts(next, PAGE_SIZE, search)
            .then((d) => {
              setPosts((prev) => [...prev, ...d.items])
              setPage(d.page)
              setHasMore(d.page < d.pages)
            })
            .catch((e) => setError(String(e)))
            .finally(() => {
              setLoading(false)
              busyRef.current = false
            })
        }
      },
      { rootMargin: '200px' },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [page, hasMore, search])

  return (
    <div className="min-h-screen bg-[#EDEDED]">
      {/* search (scrolls with the page, not fixed) */}
      <div className="bg-white/95 px-4 py-2">
        <div className="flex items-center gap-2 rounded-full bg-[#F2F2F2] px-3 py-1.5">
          <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0 text-[#9A9A9A]" fill="currentColor">
            <path d="M15.5 14h-.79l-.28-.27a6.5 6.5 0 1 0-.7.7l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0A4.5 4.5 0 1 1 14 9.5 4.5 4.5 0 0 1 9.5 14z" />
          </svg>
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') setSearch(searchInput.trim())
            }}
            placeholder="搜索朋友圈内容…"
            className="w-full bg-transparent text-[14px] text-[#333] outline-none placeholder:text-[#B0B0B0]"
          />
          {search && (
            <button
              type="button"
              className="text-[12px] text-[#576B95]"
              onClick={() => {
                setSearch('')
                setSearchInput('')
              }}
            >
              清除
            </button>
          )}
        </div>
      </div>

      <main className="mx-auto max-w-xl">
        {error && (
          <p className="px-4 py-3 text-center text-[13px] text-red-500">{error}</p>
        )}

        {search && (
          <p className="px-4 pt-3 text-[12px] text-[#9A9A9A]">
            搜索 “{search}” — 共 {total} 条
          </p>
        )}

        <section className="bg-white">
          {posts.map((p) => (
            <PostCard key={p.tid} post={p} />
          ))}
        </section>

        {loading && (
          <p className="py-4 text-center text-[13px] text-[#9A9A9A]">加载中…</p>
        )}
        {!loading && !hasMore && total > 0 && (
          <p className="py-6 text-center text-[12px] text-[#B0B0B0]">
            已经到底了 · 共 {total} 条朋友圈
          </p>
        )}
        <div ref={sentinelRef} className="h-2" />
      </main>
    </div>
  )
}
