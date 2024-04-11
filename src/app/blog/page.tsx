import { Button, Text, Title } from "@mantine/core"
import { getAllPosts } from "./_fs/posts"
import Link from "next/link"
import { convertISOtoDateStr } from "@/utils/utils"

const Page = async () => {
    const posts = await getAllPosts()

    // TODO: CreatedAt

    return (
        <>
            <Title order={1} mb="xl">
                Blog posts
            </Title>
            {posts.map(i => (
                <Button
                    key={i.slug}
                    component={Link}
                    title={i.title}
                    href={`/blog/${i.slug}`}
                    w="100%"
                    variant="subtle"
                    mb={2}
                    fz="1.1rem"
                    justify="left"
                    h="auto"
                    p="xs"
                    ta="left"
                >
                    {i.title}
                    <Text pl="sm">({convertISOtoDateStr(i.createdAtISO)})</Text>
                </Button>
            ))}
        </>
    )
}

export default Page
