import MDArticle from "@/components/MDArticle/MDArticle"
import { getPostBySlug } from "./_fs/posts"
import { FC } from "react"
import { getAllPosts } from "../_fs/posts"
import { Metadata, ResolvingMetadata } from "next"
import { GlobalData } from "@/config"

interface Params {
    slug: string
}

export const generateStaticParams = async (): Promise<Params[]> => {
    const posts = await getAllPosts()

    return posts.map(i => ({ slug: i.slug }))
}

export const generateMetadata = async (
    { params }: { params: Promise<Params> },
    _: ResolvingMetadata
): Promise<Metadata> => {
    const { slug } = await params
    const post = await getPostBySlug(slug)

    return {
        title: `${post.title} | Print3M`,
        description: post.description,
        twitter: {
            card: "summary_large_image",
            title: post.title,
            description: post.description,
            images: `${GlobalData.url}${post.thumbnail}`,
        },
        openGraph: {
            type: "article",
            title: post.title,
            description: post.description,
            publishedTime: post.createdAt,
            url: `/blog/${post.slug}`,
            images: post.thumbnail && `${GlobalData.url}${post.thumbnail}`,
        },
    }
}

const Page: FC<{ params: Promise<Params> }> = async ({ params }) => {
    const { slug } = await params
    const post = await getPostBySlug(slug)

    return (
        <MDArticle
            mdx={post.mdx}
            info={`Created at: ${post.createdAt}`}
            title={post.title}
            returnButton={{
                text: "All posts",
                href: "/",
            }}
        />
    )
}

export default Page
