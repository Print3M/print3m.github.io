import { Flex } from "@mantine/core"
import { Directory_Out, File_Out, Node_Out } from "fs/notes"
import Link from "next/link"
import { FC } from "react"

const INDENT = 3

const isDir = (obj: Node_Out): obj is Directory_Out => "children" in obj
const isLast = (index: number, list: any[]) => index === list.length - 1
const space = (num: number) => "&nbsp;".repeat(num)

interface NestedData {
    num: number
    continued: Set<number>
}

const getLines = (nested: NestedData, empty: boolean = false) => {
    let result = ""

    for (let i = 0; i < nested.num; i++) {
        const isContinued = nested.continued.has(i)

        if (i === nested.num - 1) {
            // Last round
            if (empty) {
                return result + (isContinued ? `│${space(INDENT)}` : `${space(INDENT - 1)}`)
            }
            return result + (isContinued ? "├" : "└") + "─".repeat(INDENT - 1)
        }

        result += isContinued ? `│${space(INDENT)}` : `${space(INDENT + 1)}`
    }

    return result
}

const Node: FC<{ node: Node_Out; nested: NestedData }> = ({ node, nested }) => {
    if (isDir(node)) {
        return <Directory data={node} nested={nested} />
    } else {
        return <File data={node} nested={nested} />
    }
}

const File: FC<{ data: File_Out; nested: NestedData }> = ({ data, nested }) => {
    return (
        <div>
            <span dangerouslySetInnerHTML={{ __html: getLines(nested) }} />
            {' '}<Link href={`/notes/${data.slug}`}>{data.name}</Link>
        </div>
    )
}

const Directory: FC<{ data: Directory_Out; nested: NestedData }> = ({ data, nested }) => {
    return (
        <div>
            <div>
                <span dangerouslySetInnerHTML={{ __html: getLines(nested) }} /> {data.name}
            </div>

            <Flex direction="column" gap={0} sx={{ marginTop: 0 }}>
                {data.children.map((item, i, arr) => (
                    <Node
                        key={item.name}
                        node={item}
                        nested={{
                            num: nested.num + 1,
                            continued: isLast(i, arr)
                                ? nested.continued
                                : new Set([...nested.continued, nested.num]),
                        }}
                    />
                ))}
            </Flex>
            <span dangerouslySetInnerHTML={{ __html: getLines(nested, true) }} />
        </div>
    )
}

const NotesTree:FC<{tree: Node_Out}> = ({ tree }) => (
    <Node node={tree} nested={{ num: 0, continued: new Set() }} />
)

export default NotesTree