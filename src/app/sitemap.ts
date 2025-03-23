import { GlobalData } from "@/config"
import { MetadataRoute } from "next"
import { getAllNotes } from "./notes/fs/tree"
import { getAllPosts } from "./blog/_fs/posts"

export const dynamic = "force-static"

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
    const notes = await getAllNotes()
    const posts = await getAllPosts()

    const noteUrls = notes.map(i => ({
        url: `${GlobalData.url}/notes/${i.slug}`,
        priority: 0.7,
        changeFrequency: "monthly",
    })) satisfies MetadataRoute.Sitemap

    const blogUrls = posts.map(i => ({
        url: `${GlobalData.url}/blog/${i.slug}`,
        priority: 0.8,
        changeFrequency: "monthly",
    })) satisfies MetadataRoute.Sitemap

    return [
        {
            url: `${GlobalData.url}`,
            changeFrequency: "monthly",
            priority: 1.0,
        },
        {
            url: `${GlobalData.url}/blog`,
            changeFrequency: "weekly",
            priority: 0.9,
        },
        ...blogUrls,
        {
            url: `${GlobalData.url}/notes`,
            changeFrequency: "weekly",
            priority: 0.8,
        },
        ...noteUrls,
    ]
}
