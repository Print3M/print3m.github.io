import "server-only"

import * as dree from "dree"
import matter from "gray-matter"
import fs from "fs"
import { getDateStr } from "@/utils/utils"
import { PostMetadata } from "./types"

interface Frontmatter {
    title: string
}

export const getPostMetadata = (path: string) => {
    const createdAt = getDateStr(fs.statSync(path).birthtime)
    const metadata = matter.read(path).data as Frontmatter
    const slug = path.replace('.md', '').split("/").slice(-1)[0]!

    return {
        slug,
        createdAt,
        title: metadata.title,
    } satisfies PostMetadata
}

export const getAllPostsMetadata = async () => {
    const root = await dree.scanAsync(`_blog/`, {
        symbolicLinks: false,
        excludeEmptyDirectories: true,
        depth: 1,
    })

    const files = (root.children || []).filter(i => i.type == dree.Type.FILE)

    let posts: PostMetadata[] = []

    for (const file of files) {
        posts.push(getPostMetadata(file.path))
    }

    return posts
}
