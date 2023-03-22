import { Button, Center, Divider, Flex, MediaQuery, Space, Text } from "@mantine/core"
import Link from "next/link"
import { FC } from "react"

const SubPageButton: FC<{ href: string; title: string; children: JSX.Element | string }> = ({
    children,
    href,
    title,
}) => (
    <Link href={href} title={title} passHref>
        <Button variant="light" w={140}>
            {children}
        </Button>
    </Link>
)

const Home = () => (
    <>
        <MediaQuery largerThan="sm" styles={{ display: "none" }}>
            <Space h={50} />
        </MediaQuery>
        <Space h={50} />
        <Text sx={{ textAlign: "center", margin: "auto", maxWidth: 600 }}>
            I write the notes for myself. I write the blog for people. I'm focused on IT security,
            low-level, Linux and Windows topics. Have fun. 🧠
        </Text>
        <Space h="lg" />
        <Divider label="IT security" variant="dashed" labelPosition="center" />
        <Space h="xl" />
        <Flex gap={20} justify="center">
            <SubPageButton href="/notes" title="Notes">
                Notes
            </SubPageButton>
            <SubPageButton href="/blog" title="Blog">
                Blog
            </SubPageButton>
        </Flex>
    </>
)

export default Home
