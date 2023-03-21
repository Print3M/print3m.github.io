import { Center, Container, Drawer, Flex, Stack } from "@mantine/core"
import { FC, useEffect, useState } from "react"
import { Divider, Navbar, NavLink, Space, Text } from "@mantine/core"
import { IconMarkdown, IconNews } from "@tabler/icons-react"
import { Burger, MediaQuery, useMantineTheme } from "@mantine/core"
import Link from "next/link"
import { useRouter } from "next/router"

const NavContent = () => (
    <>
        <Navbar.Section grow>
            <Space h="sm" />
            <Center sx={{ fontSize: 36, fontWeight: 900 }}>
                <Text sx={{ color: "#fff" }}>Print3M</Text>
                <Text
                    sx={{
                        color: "#0079d6",
                        fontSize: 14,
                        marginTop: 16,
                        width: 48,
                        whiteSpace: "nowrap",
                    }}
                >
                    {"'"}s hub
                </Text>
            </Center>
        </Navbar.Section>

        <Navbar.Section grow>
            <Divider label="// IT security" />
            {/* <NavLink label="Files to loot" icon={<IconFile size={20} />} /> */}
            {/* <NavLink label="Checklists" icon={<IconList size={20} />} /> */}
            <Link href="/notes" style={{ textDecoration: "none" }} title="Notes">
                <NavLink label="Notes" icon={<IconMarkdown size={20} />} />
            </Link>
            <Link href="/blog" style={{ textDecoration: "none" }} title="Blog">
                <NavLink label="Blog" icon={<IconNews size={20} />} />
            </Link>
        </Navbar.Section>
    </>
)

const SideNav = () => (
    <Navbar
        width={{ base: 240 }}
        style={{ position: "fixed" }}
        p="sm"
        hiddenBreakpoint="sm"
        hidden={true}
    >
        <NavContent />
    </Navbar>
)

const TopNav: FC<{ isOpen: boolean; toggleIsOpen: () => void }> = ({ isOpen, toggleIsOpen }) => {
    const theme = useMantineTheme()

    return (
        <MediaQuery largerThan="sm" styles={{ display: "none" }}>
            <Container
                sx={{
                    backgroundColor: theme.colors.dark[9],
                    display: "flex",
                    position: "fixed",
                    width: "100%",
                    height: 40,
                    alignItems: "center",
                    fontWeight: 900,
                }}
            >
                <Burger
                    opened={isOpen}
                    onClick={toggleIsOpen}
                    size="sm"
                    color={theme.colors.gray[6]}
                    mr="xl"
                />
                <Text sx={{ color: "#fff" }}>Print3M</Text>
                <Text
                    sx={{
                        color: "#0079d6",
                        fontSize: 14,
                        marginTop: 4,
                        whiteSpace: "nowrap",
                    }}
                >
                    {"'"}s hub
                </Text>
            </Container>
        </MediaQuery>
    )
}

const Mobile: FC<{}> = () => {
    const [isHamburgerOpen, setIsHamburgerOpen] = useState(false)
    const router = useRouter()

    useEffect(() => {
        const handler = () => {
            setIsHamburgerOpen(false)
        }
        router.events.on("routeChangeStart", handler)

        return () => router.events.off("routeChangeStart", handler)
    })

    return (
        <>
            <TopNav
                isOpen={isHamburgerOpen}
                toggleIsOpen={() => setIsHamburgerOpen(!isHamburgerOpen)}
            />
            <Drawer opened={isHamburgerOpen} onClose={() => setIsHamburgerOpen(false)}>
                <Stack>
                    <NavContent />
                </Stack>
            </Drawer>
        </>
    )
}

const Layout: FC<{ children: JSX.Element }> = ({ children }) => (
    <>
        <Mobile />
        <Flex>
            <SideNav />
            <Container p="sm" style={{ width: "100%" }}>
                <MediaQuery largerThan="sm" styles={{ display: "none" }}>
                    <Space h={50} />
                </MediaQuery>
                <MediaQuery smallerThan="sm" styles={{ display: "none" }}>
                    <Space h={35} />
                </MediaQuery>
                {children}
            </Container>
        </Flex>
    </>
)

export default Layout
