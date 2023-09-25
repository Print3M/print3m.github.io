import { Button, Divider, Flex, MediaQuery, Space, Text } from "@mantine/core"
import Head from "next/head"
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

const Section: FC<{ text: string; label: string; bottom: JSX.Element }> = ({
    text,
    label,
    bottom,
}) => (
    <section>
        <Divider label={label} variant="dashed" labelPosition="center" />
        <Space h="lg" />
        <Text sx={{ textAlign: "center", margin: "auto", maxWidth: 600 }}>{text}</Text>
        <Space h="lg" />
        <div>{bottom}</div>
    </section>
)

const Home = () => (
    <>
        <Head>
            <title>Print3M&apos;s Hub</title>
        </Head>
        <MediaQuery largerThan="sm" styles={{ display: "none" }}>
            <Space h={50} />
        </MediaQuery>

        <Space h={50} />

        <Flex direction="column" gap={50}>
            <Section
                label="IT security"
                text="I write the notes for myself. I write the blog for people. I'm focused on IT
            security, low-level, Linux and Windows topics. Have fun. 🧠"
                bottom={
                    <Flex gap={20} justify="center">
                        <SubPageButton href="/notes" title="Notes">
                            Notes
                        </SubPageButton>
                        <SubPageButton href="/blog" title="Blog">
                            Blog
                        </SubPageButton>
                    </Flex>
                }
            />

            <Section
                label="Other"
                text="Hobby interactive political map of the world with international organizations and other
            interesting facts. 🗺️"
                bottom={
                    <Flex justify="center">
                        <SubPageButton href="/world-map" title="World Map">
                            World Map
                        </SubPageButton>
                    </Flex>
                }
            />
        </Flex>
    </>
)

export default Home
