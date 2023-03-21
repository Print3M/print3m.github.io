import { FC } from "react"
import { getAllBlogPostSlugs, getBlogPostBySlug } from "fs/blog"
import { MDXSource } from "utils/types"
import MDArticle from "components/MDArticle"

export const getStaticPaths = async () => {
    const slugs = getAllBlogPostSlugs()

    return {
        paths: slugs.map(i => ({ params: { slug: i } })),
        fallback: false,
    }
}

export const getStaticProps = async ({
    params,
}: {
    params: {
        slug: string
    }
}) => {
    return {
        props: await getBlogPostBySlug(params.slug),
    }
}

interface Props {
    slug: string
    meta: {
        title: string
        date: string
    }
    source: MDXSource
}

const BlogPost: FC<Props> = ({ slug, meta, source }) => (
    <MDArticle 
        returnHref='/blog'
        title={meta.title}
        source={source}
        info={`Published: ${meta.date}`} 
    />
)

export default BlogPost
