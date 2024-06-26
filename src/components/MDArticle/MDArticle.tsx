import { Box, Button, Space, Title } from "@mantine/core"
import { IconArrowBackUp } from "@tabler/icons-react"
import Link from "next/link"
import { FC } from "react"
import { MDX } from "@/types"
import MDRenderer from "./MDRenderer/MDRenderer"

/*
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
*/

interface MDArticleProps {
    mdx: MDX
    returnButton: {
        text: string | JSX.Element
        href: string
    }
    title: JSX.Element | string
    info?: JSX.Element | string
}

const MDArticle: FC<MDArticleProps> = ({ mdx, title, info, returnButton }) => (
    <>
        <Button
            component={Link}
            href={returnButton.href}
            variant="subtle"
            leftSection={<IconArrowBackUp />}
        >
            {returnButton.text}
        </Button>
        <Space h="md" />
        <Title order={1}>{title}</Title>
        <Box pt={6} fz="md">
            {info}
        </Box>
        <MDRenderer mdx={mdx} />
    </>
)

export default MDArticle
