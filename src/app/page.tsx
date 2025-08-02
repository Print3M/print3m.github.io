import BasicLayout from "@/components/BasicLayout/BasicLayout"
import { Box, Group, Stack, Title } from "@mantine/core"
import Link from "next/link"
import { generateRss, getAllPosts } from "./blog/_fs/posts"
import { IconRss } from "@tabler/icons-react"
import BlogPostButton from "@/components/BlogPostButton/BlogPostButton"

const Page = async () => {
    const posts = await getAllPosts()
    await generateRss(posts)

    return (
        <>
            <BasicLayout>
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
            </BasicLayout>
        </>
    )
}

export default Page
