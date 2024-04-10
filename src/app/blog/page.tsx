import { Box, Button, Title } from "@mantine/core"
import { getAllPostsMetadata } from "./_fs/posts"
import Link from "next/link"

const Page = async () => {
    const posts = await getAllPostsMetadata()

    // TODO: CreatedAt

    return (
        <Box maw={600} mx="auto" mt="md">
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
                    variant="light"
                    mb="sm"
                >
                    {i.title}
                </Button>
            ))}
        </Box>
    )
}

export default Page
