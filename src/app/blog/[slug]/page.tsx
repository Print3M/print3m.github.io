import MDArticle from "@/components/MDArticle/MDArticle"
import { getPostBySlug } from "./_fs/posts"
import { FC } from "react"
import { getAllPosts } from "../_fs/posts"

interface Params {
    slug: string
}

export const generateStaticParams = async (): Promise<Params[]> => {
    const posts = await getAllPosts()

    return posts.map(i => ({ slug: i.slug }))
}

const Page: FC<{ params: Params }> = async ({ params }) => {
    const post = await getPostBySlug(params.slug)

    return (
        <MDArticle
            mdx={post.mdx}
            info={`Created at: ${post.createdAt}`}
            title={post.title}
            returnButton={{
                text: "All posts",
                href: "/blog",
            }}
        />
    )
}

export default Page
