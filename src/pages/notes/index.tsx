import { Box, Container, Space, Title } from "@mantine/core"
import SearchBar from "components/pages/Notes/SearchBar/SearchBar"
import NotesTree from "components/pages/Notes/Tree"
import { getNotesTree, Node_Out } from "fs/notes"
import Head from "next/head"
import { FC } from "react"
import { getPageTitle } from "utils/utils"

const _getLastUpdateDate = () => {
    // Built-time is the date of the last update
    const date = new Date()

    return date.toLocaleDateString("en-gb")
}

export const getStaticProps = async (): Promise<{
    props: { tree: Node_Out | undefined; lastUpdate: string }
}> => {
    const { tree } = await getNotesTree()

    return {
        props: {
            tree,
            lastUpdate: _getLastUpdateDate(),
        },
    }
}

interface Props {
    tree?: Node_Out
    lastUpdate: string
}

const Notes: FC<Props> = ({ tree, lastUpdate }) => (
    <>
        <Head>
            <title>{getPageTitle("IT notes & cheat-sheets")}</title>
        </Head>
        <Title order={1}>Notes</Title>
        <Space h="sm" />
        <Container p={0} fz="md">
            Last update: {lastUpdate}
        </Container>
        <Space h="xl" />
        <SearchBar />
        <Space h="xl" />
        <Box lh={1.3} ff="monospace">
            {tree && <NotesTree tree={tree} />}
        </Box>
    </>
)

export default Notes
