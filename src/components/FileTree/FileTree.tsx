import { Directory, NoteMetadata, TreeNode, isDirectory } from "@/app/notes/fs/types"
import { Anchor, Flex } from "@mantine/core"
import { FC } from "react"
import classes from "./FileTree.module.css"

const INDENT = 1

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
            return result + (isContinued ? "├" : "└") + "".repeat(INDENT - 1)
        }

        result += isContinued ? `│${space(INDENT)}` : `${space(INDENT + 1)}`
    }

    return result
}

const Node: FC<{ node: TreeNode; nested: NestedData }> = ({ node, nested }) => {
    if (isDirectory(node)) {
        return <TreeNodeDir node={node} nested={nested} />
    } else {
        return <TreeNodeNote node={node} nested={nested} />
    }
}

const TreeNodeNote: FC<{ node: NoteMetadata; nested: NestedData }> = ({ node, nested }) => (
    <div>
        <span dangerouslySetInnerHTML={{ __html: getLines(nested) }} />{" "}
        <Anchor href={`/notes/${node.slug}`} title={node.title}>
            {node.name}
        </Anchor>
    </div>
)

const TreeNodeDir: FC<{ node: Directory; nested: NestedData }> = ({ node, nested }) => (
    <div>
        <div>
            <span dangerouslySetInnerHTML={{ __html: getLines(nested) }} /> {node.title}
        </div>

        <Flex direction="column" gap={0} mt={0}>
            {node.children.map((item, i, arr) => (
                <Node
                    key={item.title}
                    node={item}
                    nested={{
                        num: nested.num + 1,
                        continued: isLast(i, arr)
                            ? nested.continued
                            : new Set([...Array.from(nested.continued), nested.num]),
                    }}
                />
            ))}
        </Flex>
        <span dangerouslySetInnerHTML={{ __html: getLines(nested, true) }} />
    </div>
)

const FileTree: FC<{ tree: TreeNode }> = ({ tree }) => (
    <div className={classes.wrapper}>
        <Node node={tree} nested={{ num: 0, continued: new Set() }} />
    </div>
)

export default FileTree
