import MDArticle from "components/MDArticle"
import { getNoteBySlug, getNotesTree } from "fs/notes"
import path from "path"
import { FC } from "react"
import { MDXSource } from "utils/types"

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
    lastUpdate: string
    meta: {
        title: string
        date: string
    }
    mdxSource: MDXSource
}

const Note: FC<Props> = ({ meta, mdxSource, lastUpdate }) => (
    <>
        <MDArticle
            returnHref="/notes"
            title={meta.title}
            source={mdxSource}
            info={`Last update: ${lastUpdate}`}
        />
    </>
)

export default Note
