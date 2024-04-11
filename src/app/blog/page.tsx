import { Box, Button, Title } from "@mantine/core"
import { getAllPostsMetadata } from "./_fs/posts"
import Link from "next/link"

const Page = async () => {
    const posts = await getAllPostsMetadata()

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
                    mb="xs"
                    fz="1.1rem"
                    justify="left"
                >
                    {i.title}
                </Button>
            ))}
        </>
    )
}

export default Page
