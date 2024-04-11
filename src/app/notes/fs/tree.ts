import * as dree from "dree"
import { Directory, NoteMetadata, TreeNode, isDirectory } from "./types"
import { getNoteMetadataByPath } from "./note"

const _convertDreeToTree = async (dreeData: dree.Dree) => {
    if (dreeData.type == dree.Type.FILE) return getNoteMetadataByPath(dreeData.path)

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

const _getAllNotes = (node: TreeNode): NoteMetadata[] => {
    if (!isDirectory(node)) return [node]

    let children: NoteMetadata[] = []
    for (const child of node.children) {
        for (const item of _getAllNotes(child)) {
            children.push(item)
        }
    }

    return children
}

export const getAllNotes = async () => {
    const tree = await getTree()

    return _getAllNotes(tree)
}
