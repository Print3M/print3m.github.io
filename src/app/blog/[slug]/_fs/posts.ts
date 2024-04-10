import fs from "fs"
import { serialize } from "next-mdx-remote/serialize"
import rehypePrettyCode from "rehype-pretty-code"
import { PostMetadata } from "../../_fs/types"
import { MDX } from "@/types"
import { getPostMetadata } from "../../_fs/posts"

interface Post extends PostMetadata {
    mdx: MDX
}

export const getPostBySlug = async (slug: string) => {
    const path = `_blog/${slug}.md`
    const file = fs.readFileSync(path)
    const mdx = await serialize(file.toString(), {
        parseFrontmatter: true,
        mdxOptions: { rehypePlugins: [[rehypePrettyCode as any, { theme: "aurora-x" }]] },
    })
    const metadata = getPostMetadata(path)

    return {
        ...metadata,
        mdx: mdx.compiledSource,
    } satisfies Post
}
