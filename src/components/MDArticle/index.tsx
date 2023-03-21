import { Container, createStyles, Flex, Title, TypographyStylesProvider } from "@mantine/core"
import { IconArrowBackUp } from "@tabler/icons-react"
import { MDXRemote } from "next-mdx-remote"
import Link from "next/link"
import { FC } from "react"
import { MDXSource } from "utils/types"

const Return: FC<{ href: string }> = ({ href }) => (
    <Link href={href}>
        <Flex align="center" gap={5}>
            <IconArrowBackUp />
            Return
        </Flex>
    </Link>
)

interface MDArticleProps {
    returnHref: string
    title: string
    source: MDXSource
    info?: JSX.Element | string
}

const useStyles = createStyles(() => ({
    markdown: {
        "h2, h3, h3, h4, h5, h6": {
            marginTop: 14,
            marginBottom: 10,
        },
        ul: {
            lineHeight: 1,
            marginTop: 0,
        },
        blockquote: {
            fontSize: "1rem",
        },
        p: {
            marginBottom: 10,
        },
    },
}))

const MDArticle: FC<MDArticleProps> = ({ source, returnHref, title, info }) => {
    const { classes } = useStyles()

    return (
        <div>
            <Return href={returnHref} />
            <Title order={1} sx={{ marginTop: 30 }}>
                {title}
            </Title>
            <Container sx={{ padding: 0, marginTop: 15, marginBottom: 12, fontSize: "0.95rem" }}>
                {info}
            </Container>
            <TypographyStylesProvider sx={{ textAlign: "justify" }} className={classes.markdown}>
                <MDXRemote {...source} />
            </TypographyStylesProvider>
        </div>
    )
}

export default MDArticle
