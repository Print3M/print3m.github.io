import { PostMetadata } from "@/app/blog/_fs/types"
import { Card, Text } from "@mantine/core"
import Link from "next/link"
import { FC } from "react"

interface Props extends PostMetadata {}

const BlogPostButton: FC<Props> = ({ slug, createdAt, title }) => (
    <Card padding="sm" component={Link} href={`/blog/${slug}`}>
        <Text size="lg" fw="bold" style={{ color: "var(--mantine-primary-color-light-color)" }}>
            {title}
        </Text>

        <Text pt={4} c="dimmed" size="sm">
            {createdAt}
        </Text>
    </Card>
)

export default BlogPostButton
