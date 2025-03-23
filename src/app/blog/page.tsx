import { Box, Group, Stack, Text, Title } from "@mantine/core"
import { generateRss, getAllPosts } from "./_fs/posts"
import BlogPostButton from "@/components/BlogPostButton/BlogPostButton"
import { IconRss } from "@tabler/icons-react"
import Link from "next/link"

const Page = async () => {
    const posts = await getAllPosts()
    await generateRss(posts)

    return (
        <>
            <Group align="baseline" justify="space-between">
                <Title order={1} mb="xl">
                    Blog posts
                </Title>

                <Link href="/blog-rss.xml" target="_blank" style={{ textDecoration: "none" }}>
                    <Group c="orange" gap={5}>
                        RSS
                        <Box pt={4}>
                            <IconRss />
                        </Box>
                    </Group>
                </Link>
            </Group>
            <Stack gap="md">
                {posts.map(props => (
                    <BlogPostButton {...props} key={props.slug} />
                ))}
            </Stack>
        </>
    )
}

export default Page
