import { FC } from "react"
import { getAllNotes } from "../fs/tree"
import MDArticle from "@/components/MDArticle/MDArticle"
import { getNoteBySlug } from "../fs/note"

interface Params {
    slug: string
}

export const generateStaticParams = async () => {
    const notes = await getAllNotes()

    return notes.map(i => ({ slug: i.slug })) satisfies Params[]
}

const Page: FC<{ params: Promise<Params> }> = async ({ params }) => {
    const { slug } = await params
    const note = await getNoteBySlug(slug)

    return (
        <>
            <MDArticle
                mdx={note.mdx}
                returnButton={{
                    text: "All notes",
                    href: "/notes",
                }}
                title={note.title}
            />
        </>
    )
}

export default Page
