import FileTree from "@/components/FileTree/FileTree"
import { getTree } from "./fs/tree"
import { Title } from "@mantine/core"

const Page = async () => {
    const tree = await getTree()

    return (
        <>
            <Title order={1} pb="lg">
                Notes & cheat-sheets
            </Title>
            <FileTree tree={tree} />
        </>
    )
}

export default Page
