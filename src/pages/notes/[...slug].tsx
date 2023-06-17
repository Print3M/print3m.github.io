import MDArticle from "components/MDArticle"
import { getNoteBySlug, getNotesTree } from "fs/notes"
import Head from "next/head"
import path from "path"
import { FC } from "react"
import { MDXSource } from "utils/types"
import { getPageTitle } from "utils/utils"

export const getStaticPaths = async () => {
    const { slugs } = await getNotesTree()

    return {
        paths: slugs.map(i => ({ params: { slug: i.split("/") } })),
        fallback: false,
    }
}

export const getStaticProps = async ({
    params,
}: {
    params: {
        slug: string[]
    }
}) => {
    return {
        props: await getNoteBySlug(path.join(...params.slug)),
    }
}

interface Props {
    meta: {
        title: string
        date: string
    }
    mdxSource: MDXSource
}

const Note: FC<Props> = ({ meta, mdxSource }) => (
    <>
        <Head>
            <title>{getPageTitle(meta.title)}</title>
        </Head>
        <MDArticle returnHref="/notes" title={meta.title} source={mdxSource} />
    </>
)

export default Note
