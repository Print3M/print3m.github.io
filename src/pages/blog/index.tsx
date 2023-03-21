import { Container, createStyles, Divider, Flex, Text, Title } from "@mantine/core"
import { getAllBlogPostSlugs, getBlogPostBySlug } from "fs/blog"
import Link from "next/link"
import { FC } from "react"

const useStyles = createStyles(_ => ({
    itemsContainer: {
        marginTop: 45,
    },
    item: {
        maxWidth: 500,

        ".bottom-line": {
            marginTop: 20,
            marginBottom: 22,
        },
    },
}))

export const getStaticProps = async (): Promise<{ props: Props }> => {
    const slugs = getAllBlogPostSlugs()
    const posts: PostItem[] = []

    for (const slug of slugs) {
        const data = await getBlogPostBySlug(slug)
        posts.push({
            title: data.meta.title,
            date: data.meta.date,
            description: data.meta.description,
            slug,
        })
    }

    return {
        props: {
            totalCount: slugs.length,
            posts,
        },
    }
}

interface PostItem {
    title: string
    date: string
    slug: string
    description: string
}

interface Props {
    totalCount: number
    posts: PostItem[]
}

const Blog: FC<Props> = ({ posts, totalCount }) => {
    const { classes } = useStyles()

    return (
        <>
            <Title>Blog</Title>
            <div>All posts: {totalCount}</div>

            <div className={classes.itemsContainer}>
                {posts.map(post => {
                    return (
                        <Container size="xs" key={post.slug}>
                            <Link href={`/blog/${post.slug}`}>
                                <Title order={3}>{post.title}</Title>
                            </Link>
                            <Text sx={{ textAlign: "justify", marginTop: 18 }}>
                                {post.description}
                            </Text>
                            <Flex
                                justify="space-between"
                                align="center"
                                sx={{ margin: "20px 0 22px" }}
                            >
                                <Text size="sm">{post.date}</Text>
                                <span className="more">
                                    <Link href={`/blog/${post.slug}`}>Read more...</Link>
                                </span>
                            </Flex>
                            <Divider />
                        </Container>
                    )
                })}
            </div>
        </>
    )
}

export default Blog
