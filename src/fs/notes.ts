import directoryTree from "directory-tree"
import { serialize } from "next-mdx-remote/serialize"
import path from "path"
import fs from "fs"
import matter from "gray-matter"
import rehypePrettyCode from "rehype-pretty-code"
import { NOTES_PATH } from "./consts"

export interface Directory_In {
    path: string
    name: string
    children: Node_In[]
}

export interface File_In {
    path: string
    name: string
}

export type Node_In = Directory_In | File_In

export interface Directory_Out {
    name: string
    children: Node_Out[]
}

export interface File_Out {
    name: string
    slug: string
    title: string
}

export type Node_Out = File_Out | Directory_Out

export const isDir = (obj: Node_In): obj is Directory_In => {
    return "children" in obj
}

export const treeWalk = async (
    node: Node_In,
    fileAction: (node: File_In) => Promise<File_Out | undefined>,
    dirAction: (node: Directory_In) => Promise<Directory_Out | undefined>
): Promise<Node_Out | undefined> => {
    if (isDir(node)) {
        const newNode = await dirAction(node)

        if (!newNode) return undefined
        newNode.children = []

        // Iterate over directory nodes
        for (const [i, child] of node.children.entries()) {
            const newChild = await treeWalk(child, fileAction, dirAction)

            if (newChild !== undefined) {
                newNode.children.push(newChild)
            }
        }

        return newNode
    }

    return await fileAction(node)
}

export interface NoteItem {
    content: string
    path: string
}

export const getNotesTree = async () => {
    const tree = directoryTree(NOTES_PATH, { extensions: /\.md/, exclude: /^\..*/ }) as Node_In
    const slugs = new Set<string>()
    const notes: NoteItem[] = []
    const updatedTree = await treeWalk(
        tree,
        async file => {
            const rawContent = fs.readFileSync(file.path, "utf8")
            const { data } = matter(rawContent)
            const name = file.name.replace(/\.md$/, "")
            const slug = file.path.replace(`${NOTES_PATH}/`, "").replace(/.md$/, "")

            // Exclude not-ready and hidden files
            if (!data.title || !slug || name.startsWith(".")) return undefined

            slugs.add(slug)
            notes.push({
                content: rawContent,
                path: slug,
            })

            return {
                name,
                slug,
                title: data.title,
            } as File_Out
        },
        async dir => {
            // Exclude hidden directories
            if (dir.name.startsWith(".")) return undefined

            return {
                children: [],
                name: dir.name === "_notes" ? "notes" : `${dir.name}`,
            }
        }
    )

    // TODO: Write it better
    fs.writeFile(".next/static/notes.json", JSON.stringify({ notes }), function (err) {
        if (err) throw err
        console.log("Saved!")
    })

    return {
        slugs: [...slugs],
        tree: updatedTree,
    }
}

export const getNoteBySlug = async (slug: string) => {
    const fullPath = path.join(NOTES_PATH, `${slug}.md`)
    const stats = fs.statSync(fullPath)
    const fileContents = fs.readFileSync(fullPath, "utf8")
    const { data, content } = matter(fileContents)
    const mdxSource = await serialize(content, {
        mdxOptions: { rehypePlugins: [rehypePrettyCode] },
    })

    return {
        lastUpdate: stats.mtime.toLocaleDateString("en-GB"),
        meta: data,
        mdxSource,
    }
}
