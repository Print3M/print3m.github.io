export type TreeNode = NoteMetadata | Directory

export interface NoteMetadata {
    title: string
    slug: string
}

export interface Directory {
    title: string
    children: TreeNode[]
}
