import path from "path"
import matter from "gray-matter"
import fs from "fs"
import { serialize } from "next-mdx-remote/serialize"
import rehypePrettyCode from "rehype-pretty-code"
import { BLOG_PATH } from "./consts"

export const getBlogPostBySlug = async (slug: string) => {
    const realSlug = slug.replace(/\.md$/, "")
    const fullPath = path.join(BLOG_PATH, `${realSlug}.md`)
    const fileContents = fs.readFileSync(fullPath, "utf8")
    const { data, content } = matter(fileContents)
    const source = await serialize(content, {
        mdxOptions: {
            rehypePlugins: [rehypePrettyCode],
        },
    })

    return { slug: realSlug, meta: data, source }
}

export const getAllBlogPostSlugs = () => {
    const files = fs.readdirSync(BLOG_PATH)
    const slugs: string[] = []

    for (const file of files) {
        if (file.startsWith(".")) continue

        const slug = file.replace(/\.md$/, "")
        slugs.push(slug)
    }

    return slugs
}
