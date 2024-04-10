import { Title } from "@mantine/core"
import { useRouter } from "next/router"
import { useEffect } from "react"

const NotFound404 = () => {
    const router = useRouter()

    useEffect(() => {
        if (router.asPath.startsWith('/notes')) {
            router.push("/notes")
        }
    })

    return <Title order={1}>&lt;?php echo &quot;404 Not found&quot; ?&gt;</Title>
}

export default NotFound404
