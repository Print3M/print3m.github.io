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
            <Space h={100} />
        </MediaQuery>
        <Text sx={{ textAlign: "center", margin: "auto", maxWidth: 600 }}>
            If I lose my memory or leave this world prematurely, something will remain of me for
            posterity. 🧠
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
