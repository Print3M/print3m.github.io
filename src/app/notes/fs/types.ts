import { MDX } from "@/types"

export type TreeNode = NoteMetadata | Directory

export interface NoteMetadata {
    title: string
    name: string
    slug: string
}

export interface Note extends NoteMetadata {
    mdx: MDX
}

export interface Directory {
    title: string
    children: TreeNode[]
}

export const isDirectory = (obj: TreeNode): obj is Directory => "children" in obj
