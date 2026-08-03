import type { PostListResponse } from './types'

const API = ''

export async function fetchPosts(
  page: number,
  pageSize: number,
  search: string,
): Promise<PostListResponse> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  })
  if (search) params.set('search', search)
  const res = await fetch(`${API}/api/posts?${params}`)
  if (!res.ok) throw new Error(`API ${res.status}`)
  return res.json()
}

export function mediaUrl(file: string): string {
  return `${API}/media/${encodeURIComponent(file)}`
}
