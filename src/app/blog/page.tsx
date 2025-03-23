import { Stack, Title } from "@mantine/core"
import { generateRss, getAllPosts } from "./_fs/posts"
import BlogPostButton from "@/components/BlogPostButton/BlogPostButton"

const Page = async () => {
    const posts = await getAllPosts()
    generateRss(posts)

    return (
        <>
            <Title order={1} mb="xl">
                Blog posts
            </Title>
            <Stack gap="md">
                {posts.map(props => (
                    <BlogPostButton {...props} key={props.slug} />
                ))}
            </Stack>
        </>
    )
}

export default Page
