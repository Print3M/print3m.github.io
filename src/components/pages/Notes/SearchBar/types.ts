export interface NoteItem {
    content: string
    path: string
}

export interface FoundNote {
    path: string
    items: {
        content: string
        atChar: number
        chars: number
    }[]
}