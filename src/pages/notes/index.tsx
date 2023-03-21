import { Box, Title } from "@mantine/core"
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
        <Box sx={{ fontFamily: "monospace", lineHeight: 1.3, marginTop: 22 }}>
            {tree && <NotesTree tree={tree} />}
        </Box>
    </>
)

export default Notes
