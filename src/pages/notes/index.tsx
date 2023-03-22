import { Box, Space, Title } from "@mantine/core"
import NotesTree from "components/pages/Notes/Tree"
import { getNotesTree, Node_Out } from "fs/notes"
import { FC } from "react"

export const getStaticProps = async (): Promise<{ props: { tree: Node_Out | undefined } }> => {
    const { tree } = await getNotesTree()

    return {
        props: {
            tree,
        },
    }
}

const Notes: FC<{ tree: Node_Out | undefined }> = ({ tree }) => (
    <>
        <Title order={1}>Notes</Title>
        <Space h="xl" />
        <Box lh={1.3} ff="monospace">
            {tree && <NotesTree tree={tree} />}
        </Box>
    </>
)

export default Notes
