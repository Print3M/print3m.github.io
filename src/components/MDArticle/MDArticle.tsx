import { Box, Button, Space, Title } from "@mantine/core"
import { IconArrowBackUp } from "@tabler/icons-react"
import Link from "next/link"
import { FC, JSX } from "react"
import { MDX } from "@/types"
import MDRenderer from "./MDRenderer/MDRenderer"

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
