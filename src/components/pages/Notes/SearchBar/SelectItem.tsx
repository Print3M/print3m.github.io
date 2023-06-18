import { Box, SelectItemProps, Text } from "@mantine/core"
import { forwardRef } from "react"
import { FoundNote } from "./types"

const highlightMatched = (v: string, atChar: number, chars: number) => {
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
                    {highlightMatched(line.content, line.atChar, line.chars)}
                </Text>
            ))}
        </Box>
    </div>
))

export default SelectItem