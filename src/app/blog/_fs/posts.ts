import "server-only"

import * as dree from "dree"
import matter from "gray-matter"
import { PostMetadata } from "./types"
import { Feed } from "feed"
import path from "path"
import fs from 'fs'
import { GlobalData } from "@/config"

interface Frontmatter {
    title: string
    createdAt: string
    thumbnail?: string
    description?: string
}

export const getPostMetadata = (path: string) => {
    const metadata = matter.read(path).data as Frontmatter
    const slug = path.replace(".md", "").split("/").slice(-1)[0]!

    return {
        slug,
        createdAt: metadata.createdAt,
        title: metadata.title,
        thumbnail: metadata.thumbnail,
        description: metadata.description,
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

export const generateRss = async (posts: PostMetadata[]) => {
    const filename = "blog-rss.xml"
    const url = `${GlobalData.url}/${filename}`
    const author = {
        link: "https://x.com/Print3M_",
        name: "Print3M",
    }

    const feed = new Feed({
        title: "Print3M Blog",
        description: "Offensive IT security blog, redteaming and programming.",
        language: "en",
        copyright: "Print3M © 2025",
        id: url,
        link: url,
        author,
    })

    posts.forEach(post => {
        const url = `${GlobalData.url}/blog/${post.slug}`

        feed.addItem({
            title: post.title,
            id: url,
            link: url,
            description: post.description,
            image: `${GlobalData.url}${post.thumbnail}`,
            date: new Date(post.createdAt),
            author: [author],
        })
    })

    // Save RSS to the public directory
    const rssPath = path.join(process.cwd(), "public", filename)
    fs.writeFileSync(rssPath, feed.rss2())
    console.log(`[+] RSS feed generated at /public/${filename}`)
}
