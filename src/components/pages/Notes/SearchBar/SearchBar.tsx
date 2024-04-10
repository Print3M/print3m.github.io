import { FoundNote, NoteItem } from "./types"
import { Select } from "@mantine/core"
import { useRouter } from "next/router"
import { useEffect, useState } from "react"
import SelectItem from "./SelectItem"

const prepareMatched = (v: string, start: number, length: number) => {
    /*
        :v      - string where the keyword has been found
        :start  - index of :v string where the keyword has been found
        :length - length of the found keyword
    */
    const EXTRA = 30
    const part1 = v.substring(start - EXTRA, start).trimStart()
    const part2 = v.substring(start, start + length + EXTRA).trimEnd()

    return {
        content: part1 + part2,
        atChar: part1.length,
    }
}

const findNotes = (notes: NoteItem[], v: string, max: number) => {
    const foundNotes: FoundNote[] = []

    for (const note of notes) {
        // Only valid regex is allowed
        let regexp = null
        try {
            regexp = new RegExp(`${v}`, "gi")
        } catch {
            continue
        }
        const matched = note.content.matchAll(regexp)
        const items = Array.from(matched)

        if (items.length) {
            // Create found note if any value has been found
            const foundNote: FoundNote = {
                path: note.path,
                items: [],
            }

            for (const item of items) {
                if (item?.input && item?.index) {
                    // Include all occurences in one note
                    const matchedStr = item[0]
                    const prepared = prepareMatched(item.input, item.index, matchedStr.length)
                    foundNote.items.push({
                        content: prepared.content,
                        atChar: prepared.atChar,
                        chars: matchedStr.length,
                    })
                }
            }

            foundNotes.push(foundNote)
        }
    }

    return foundNotes
}

const prepareSelectData = (items: FoundNote[]) => {
    return items.map(i => ({ file: i, value: `/notes/${i.path}`, label: `/notes/${i.path}` }))
}

const SearchBar = () => {
    const [input, setInput] = useState("")
    const [notes, setNotes] = useState<NoteItem[] | null>(null)
    const [found, setFound] = useState<FoundNote[]>([])
    const router = useRouter()

    useEffect(() => {
        if (!!notes && input.length > 2) {
            setFound(findNotes(notes, input, 10))
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
        <Select
            label="Search notes (regex supported)"
            placeholder="/keyword/gi"
            onSearchChange={v => setInput(v)}
            searchValue={input}
            onFocus={fetchNotes}
            itemComponent={SelectItem}
            data={prepareSelectData(found)}
            onChange={e => e && router.push(e)}
            maxDropdownHeight={1000}
            filter={() => true}
            searchable
        />
    )
}

export default SearchBar
