"use client"

import { AppShell, Box, Flex, Group, Text, rem } from "@mantine/core"
import { FC, PropsWithChildren } from "react"

const Layout: FC<PropsWithChildren> = ({ children }) => (
    <AppShell bg="var(--mantine-color-dark-7" header={{ height: 60, offset: false }} padding="md">
        <AppShell.Header>
            <Group h="100%" px="md">
                <Flex align="flex-end" fw="bolder">
                    <Box c="white" fz={26}>Print3M</Box>
                    <Box c="var(--mantine-primary-color-filled)" fz={16} pb={5}fw="inherit">
                        {"'"}s harbor
                    </Box>
                </Flex>
            </Group>
        </AppShell.Header>

        <AppShell.Main pt={`calc(${rem(60)} + var(--mantine-spacing-md))`}>
            {children}

            <Box></Box>
        </AppShell.Main>

        <AppShell.Footer ta="center" mt={100} pos="static">
            <Text pt="xs" pb="xs">
                Print3M&apos;s hub © {new Date().getFullYear()}
            </Text>
        </AppShell.Footer>
    </AppShell>
)

export default Layout
