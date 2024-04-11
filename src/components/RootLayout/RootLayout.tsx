"use client"

import { GlobalData } from "@/config"
import { ActionIcon, AppShell, Box, Button, Flex, Group, Text, rem } from "@mantine/core"
import { IconBrandGithub } from "@tabler/icons-react"
import Link from "next/link"
import { FC, PropsWithChildren } from "react"

const RootLayout: FC<PropsWithChildren> = ({ children }) => (
    <AppShell bg="var(--mantine-color-dark-7" header={{ height: 60, offset: false }} padding="md">
        <AppShell.Header>
            <Group h="100%" px="md" maw={800} m="auto" justify="space-between">
                <Group justify="space-between">
                    <Flex align="flex-end" fw="bolder">
                        <Box c="white" fz={26}>
                            Print3M
                        </Box>
                        <Box c="var(--mantine-primary-color-filled)" fz={16} pb={6} fw="inherit">
                            {"'"}s Hub
                        </Box>
                    </Flex>
                </Group>
                <Group>
                    <Button component={Link} title="Home" href="/" variant="subtle">
                        Home
                    </Button>
                    <Button component={Link} title="Blog" href="/blog" variant="subtle">
                        Blog
                    </Button>
                    <Button
                        component={Link}
                        title="Notes & cheat-sheets"
                        href="/notes"
                        variant="subtle"
                    >
                        Notes
                    </Button>
                    <Button
                        component={Link}
                        color="orange"
                        title="SecuriTree.xyz"
                        href={GlobalData.securitreeUrl}
                        variant="subtle"
                    >
                        SecuriTree
                    </Button>
                    <ActionIcon
                        component={Link}
                        href={GlobalData.githubUrl}
                        title="Print3M GitHub"
                        variant="subtle"
                        w={32}
                        h={32}
                    >
                        <IconBrandGithub color="white" />
                    </ActionIcon>
                </Group>
            </Group>
        </AppShell.Header>

        <AppShell.Main pt={`calc(${rem(60)} + var(--mantine-spacing-md))`}>
            {children}
        </AppShell.Main>

        <AppShell.Footer ta="center" mt={100} pos="static">
            <Text pt="xs" pb="xs">
                Print3M&apos;s hub © {new Date().getFullYear()}
            </Text>
        </AppShell.Footer>
    </AppShell>
)

export default RootLayout
