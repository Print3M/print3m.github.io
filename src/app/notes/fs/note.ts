import "server-only"

import fs from "fs"
import matter from "gray-matter"
import { Note, NoteMetadata } from "./types"
import { serialize } from "next-mdx-remote/serialize"
import rehypePrettyCode from "rehype-pretty-code"

export const PATH_SEPARATOR = "--"

export const notePathToSlug = (path: string) => {
    const dirs = path.replace(".md", "").split("_notes/")[1]!.split("/")

    return dirs.join(PATH_SEPARATOR)
}

export const noteSlugToPath = (slug: string) => {
    const dirs = slug.split(PATH_SEPARATOR)

    return "_notes/" + dirs.join("/") + ".md"
}

export const getNoteMetadataByPath = (path: string) => {
    const metadata = matter.read(path).data as {
        title: string
    }
    const name = path.replace(".md", "").split("/").slice(-1)[0] || ""
    const dirs = path.replace(".md", "").split("_notes/")[1]!.split("/")

    return {
        name,
        title: metadata.title,
        slug: dirs.join(PATH_SEPARATOR),
    } satisfies NoteMetadata
}

const getNoteMdxByPath = async (path: string) => {
    const file = fs.readFileSync(path)
    const mdx = await serialize(file.toString(), {
        parseFrontmatter: true,
        mdxOptions: { rehypePlugins: [[rehypePrettyCode as any, { theme: "aurora-x" }]] },
    })

    return mdx.compiledSource
}

export const getNoteBySlug = async (slug: string) => {
    const path = noteSlugToPath(slug)

    return {
        ...getNoteMetadataByPath(path),
        mdx: await getNoteMdxByPath(path),
    } satisfies Note
}
