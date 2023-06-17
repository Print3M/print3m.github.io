import { Box, Select, SelectItemProps, Text } from "@mantine/core"
import { NoteItem } from "fs/notes"
import { useRouter } from "next/router"
import { forwardRef, useEffect, useState } from "react"

const trim = (v: string) => {
    return v.trim()
}

interface FoundNote {
    path: string
    items: {
        content: string
        atChar: number
        chars: number
    }[]
}

const find = (notes: NoteItem[], v: string, max: number, chars: number) => {
    const foundNotes: FoundNote[] = []

    for (const note of notes) {
        if (max-- == 0) break

        const matched = note.content.matchAll(new RegExp(`.{0,${chars}}${v}.{0,${chars}}`, "gi"))
        const items = Array.from(matched)

        if (items.length) {
            // Create found note if value has been found
            const foundNote: FoundNote = {
                path: note.path,
                items: [],
            }

            for (const item of items) {
                // Include all occurences in one note
                const trimmed = trim(item.toString())
                foundNote.items.push({
                    content: trimmed,
                    atChar: trimmed.toLowerCase().indexOf(v),
                    chars: v.length,
                })
            }

            foundNotes.push(foundNote)
        }
    }

    return foundNotes
}

const highlight = (v: string, atChar: number, chars: number) => {
    return (
        <span>
            {v.substring(0, atChar)}
            <span style={{ backgroundColor: "#d6d600", color: "black" }}>
                {v.substring(atChar, atChar + chars)}
            </span>
            {v.substring(atChar + chars)}
        </span>
    )
}

interface ItemProps extends SelectItemProps {
    file: FoundNote
}

const SelectItem = forwardRef<HTMLDivElement, ItemProps>(({ file, ...others }: ItemProps, ref) => (
    <div ref={ref} {...others}>
        <Box>
            <Text fw="bold" fz={14}>
                /{file.path}
            </Text>
            {file.items.map(line => (
                <Text ml={20} key={line.content + line.atChar} ff="monospace" fz={12} lh="1.1rem">
                    {highlight(line.content, line.atChar, line.chars)}
                </Text>
            ))}
        </Box>
    </div>
))

const prepare = (items: FoundNote[]) => {
    return items.map(i => ({ file: i, value: `/notes/${i.path}`, label: `/notes/${i.path}` }))
}

const SearchBar = () => {
    const [input, setInput] = useState("")
    const [notes, setNotes] = useState<NoteItem[] | null>(null)
    const [found, setFound] = useState<FoundNote[]>([])
    const router = useRouter()

    console.log(prepare(found), input)

    useEffect(() => {
        if (!!notes && input.length > 2) {
            setFound(find(notes, input, 10, 30))
        } else {
            setFound([])
        }
    }, [input])

    const fetchNotes = async () => {
        if (notes === null) {
            try {
                const raw = await fetch("/_next/static/notes.json")
                setNotes((await raw.json()).notes)
            } catch (e) {
                console.error(e)
            }
        }
    }

    return (
        <>
            <Select
                label="Search"
                placeholder="Keyword"
                onSearchChange={v => setInput(v)}
                searchValue={input}
                onFocus={fetchNotes}
                itemComponent={SelectItem}
                data={prepare(found)}
                onChange={e => e && router.push(e)}
                maxDropdownHeight={1000}
                filter={() => true}
                searchable
            />
        </>
    )
}

export default SearchBar
