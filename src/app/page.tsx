import BasicLayout from "@/components/BasicLayout/BasicLayout"
import { Button, Divider, Flex, Space, Text } from "@mantine/core"
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
        <Text ta="center">{text}</Text>
        <Space h="lg" />
        <div>{bottom}</div>
    </section>
)

const Page = () => (
    <BasicLayout>
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
    </BasicLayout>
)

export default Page
