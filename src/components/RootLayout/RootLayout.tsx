"use client"

import { AppShell, Burger, Group, Text, rem } from "@mantine/core"
import { FC, PropsWithChildren, useEffect } from "react"
import classes from "./RootLayout.module.css"
import { useDisclosure } from "@mantine/hooks"
import Logo from "./Logo/Logo"
import { DesktopNavigation } from "./Navigation/Navigation"
import MobileDrawer from "./MobileDrawer/MobileDrawer"
import { usePathname, useRouter } from "next/navigation"

const Hamburger = () => {
    const [opened, actions] = useDisclosure(false)
    const pathname = usePathname()

    useEffect(() => {
        actions.close()

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pathname])

    return (
        <>
            <Burger opened={opened} onClick={actions.toggle} className={classes.burger} />
            <MobileDrawer opened={opened} onClose={actions.close} />
        </>
    )
}

const RootLayout: FC<PropsWithChildren> = ({ children }) => (
    <AppShell bg="var(--mantine-color-dark-7" header={{ height: 60, offset: false }} padding="md">
        <AppShell.Header>
            <Group h="100%" px="md" maw={800} m="auto" justify="space-between">
                <Group justify="left">
                    <Hamburger />
                    <Logo />
                </Group>
                <div className={classes.navigation}>
                    <DesktopNavigation />
                </div>
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
