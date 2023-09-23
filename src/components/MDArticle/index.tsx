import {
    Container,
    createStyles,
    Flex,
    Space,
    Text,
    Title,
    TypographyStylesProvider,
} from "@mantine/core"
import { IconArrowBackUp, IconLink } from "@tabler/icons-react"
import { MDXRemote } from "next-mdx-remote"
import Link from "next/link"
import { FC } from "react"
import { MDXSource } from "utils/types"
import { slugify } from "utils/utils"

const Return: FC<{ href: string }> = ({ href }) => (
    <Link href={href}>
        <Flex align="center" gap={5}>
            <IconArrowBackUp />
            Return
        </Flex>
    </Link>
)

const useStyles = createStyles(t => ({
    markdown: {
        textAlign: "justify",
        fontFamily: "Helvetica",

        "p, code, pre, ul, li, blockquote": {
            fontSize: "1rem",
        },
        ul: {
            marginLeft: 16,
            paddingLeft: 0,
        },
        blockquote: {
            padding: 0,
            paddingLeft: 12,
            paddingTop: 3,
            paddingBottom: 0,
            margin: 0,
            borderLeft: `4px solid ${t.colors.brand[4]}`,
        },
        code: {
            fontSize: "0.92rem"
        }
    },
}))

const getHeading = (h: "h1" | "h2" | "h3" | "h4", text: string) => {
    const anchor = slugify(text)

    const h1 = (children: JSX.Element) => <h1 id={anchor}>{children}</h1>
    const h2 = (children: JSX.Element) => <h2 id={anchor}>{children}</h2>
    const h3 = (children: JSX.Element) => <h3 id={anchor}>{children}</h3>
    const h4 = (children: JSX.Element) => <h4 id={anchor}>{children}</h4>

    const a = (
        <a aria-hidden="true" tabIndex={-1} href={`#${anchor}`}>
            <Text display="inline" ml={6} sx={{ verticalAlign: "middle" }}>
                <IconLink size={18} />
            </Text>
        </a>
    )

    const content = (
        <>
            {text}
            {a}
        </>
    )

    switch (h) {
        case "h1":
            return h1(content)
        case "h2":
            return h2(content)
        case "h3":
            return h3(content)
        case "h4":
            return h4(content)
        default:
            return <></>
    }
}

interface MDArticleProps {
    returnHref: string
    title: string
    source: MDXSource
    info?: JSX.Element | string
}

const MDArticle: FC<MDArticleProps> = ({ source, returnHref, title, info }) => {
    const { classes } = useStyles()

    return (
        <div>
            <Return href={returnHref} />
            <Space h="md" />
            <Title order={1}>{title}</Title>
            <Space h="sm" />
            <Container p={0} fz="md">
                {info}
            </Container>
            <Space h="sm" />
            <TypographyStylesProvider className={classes.markdown}>
                <MDXRemote
                    {...source}
                    components={{
                        h1: props => getHeading("h1", props.children?.toString() || ""),
                        h2: props => getHeading("h2", props.children?.toString() || ""),
                        h3: props => getHeading("h3", props.children?.toString() || ""),
                        h4: props => getHeading("h4", props.children?.toString() || ""),
                    }}
                />
            </TypographyStylesProvider>
        </div>
    )
}

export default MDArticle
