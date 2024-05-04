import "server-only"

import * as dree from "dree"
import matter from "gray-matter"
import { PostMetadata } from "./types"

interface Frontmatter {
    title: string
    createdAt: string
}

export const getPostMetadata = (path: string) => {
    const metadata = matter.read(path).data as Frontmatter
    const slug = path.replace(".md", "").split("/").slice(-1)[0]!

    return {
        slug,
        createdAt: metadata.createdAt,
        title: metadata.title,
    } satisfies PostMetadata
}

export const getAllPosts = async () => {
    const root = await dree.scanAsync(`_blog/`, {
        symbolicLinks: false,
        excludeEmptyDirectories: true,
        depth: 1,
        showHidden: false,
    })

    const files = (root.children || []).filter(i => i.type == dree.Type.FILE)

    let posts: PostMetadata[] = []

    for (const file of files) {
        posts.push(getPostMetadata(file.path))
    }

    return posts.sort((a, b) => {
        // Sort by latest
        const dateA = new Date(a.createdAt)
        const dateB = new Date(b.createdAt)

        return dateA > dateB ? -1 : dateA < dateB ? 1 : 0
    })
}
