import * as dree from "dree"
import matter from "gray-matter"
import { Directory, NoteMetadata, TreeNode } from "./types"

interface Frontmatter {
    title: string
}

const getNoteMetadata = (path: string) => {
    const metadata = matter.read(path).data as Frontmatter
    const dirs = path.replace(".md", "").split("_notes/")[1]!.split("/")

    return {
        title: metadata.title,
        slug: dirs.join("-"),
    } satisfies NoteMetadata
}

const _convertDreeToTree = async (dreeData: dree.Dree) => {
    if (dreeData.type == dree.Type.FILE) return getNoteMetadata(dreeData.path)

    let children: TreeNode[] = []
    for (const child of dreeData.children || []) {
        const item = await _convertDreeToTree(child)

        if (item) children.push(item)
    }

    return {
        title: dreeData.name,
        children,
    } satisfies Directory
}

export const getTree = async () => {
    const dreeRoot = await dree.scanAsync(`_notes/`, {
        symbolicLinks: false,
        excludeEmptyDirectories: true,
        showHidden: false,
    })

    return await _convertDreeToTree(dreeRoot)
}
