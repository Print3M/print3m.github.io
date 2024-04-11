import FileTree from "@/components/FileTree/FileTree"
import { getTree } from "./fs/tree"

const Page = async () => {
    const tree = await getTree()

    return <FileTree tree={tree} />
}

export default Page
