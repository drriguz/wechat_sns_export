export interface Like {
  create_time: number
  create_time_str: string
  type: number
  type_name: string
  username: string
  nickname: string
  to_username: string
  to_nickname: string
  content: string
  comment_id: number
}

export interface Comment extends Like {}

export interface MediaItem {
  media_id: string
  type: string
  width: number
  height: number
  file: string
  thumb_file: string
}

export interface LinkCard {
  title: string
  description: string
  source: string
  thumb_url: string
}

export interface FinderCard {
  nickname: string
  desc: string
  avatar: string
  thumb_url: string
  video_url: string
}

export interface Post {
  tid: number
  id: string
  username: string
  nickname: string
  create_time: number
  create_time_str: string
  content_desc: string
  content_type: number
  content_type_name: string
  is_private: boolean
  location: { latitude: string; longitude: string; poi_name: string } | null
  likes: Like[]
  comments: Comment[]
  link_url: string
  link: LinkCard | null
  finder: FinderCard | null
  media: MediaItem[]
}

export interface PostListResponse {
  items: Post[]
  page: number
  page_size: number
  total: number
  pages: number
}
