import { Center, Container, Drawer, Flex, Footer, Stack } from "@mantine/core"
import { FC, useEffect, useState } from "react"
import { Divider, Navbar, NavLink, Space, Text } from "@mantine/core"
import { IconBrandGithub, IconHome, IconMarkdown, IconNews, IconWorld } from "@tabler/icons-react"
import { Burger, MediaQuery } from "@mantine/core"
import Link from "next/link"
import { useRouter } from "next/router"

const CustomNavLink: FC<{
    icon: JSX.Element
    href: string
    title: string
    children: string
    targetBlank?: boolean
}> = ({ icon, href, title, children, targetBlank }) => (
    <Link
        href={href}
        style={{ textDecoration: "none" }}
        title={title}
        target={targetBlank ? "_blank" : "_self"}
    >
        <NavLink label={children} icon={icon} />
    </Link>
)

const NavContent = () => (
    <>
        <Navbar.Section grow>
            <Space h="sm" />
            <Center fz={36} fw={900}>
                <Text c="white">Print3M</Text>
                <Text
                    sx={t => ({
                        color: t.colors.brand[4],
                        fontSize: 14,
                        marginTop: 16,
                        width: 48,
                        whiteSpace: "nowrap",
                    })}
                >
                    {"'"}s hub
                </Text>
            </Center>
            <Space h="sm" />
            <CustomNavLink
                href="https://github.com/Print3M"
                title="GitHub"
                icon={<IconBrandGithub size={20} />}
                targetBlank
            >
                GitHub
            </CustomNavLink>
        </Navbar.Section>

        <Navbar.Section grow>
            <CustomNavLink href="/" title="Home" icon={<IconHome size={20} />}>
                Home
            </CustomNavLink>
            <Space h="md" />
            <Divider label="// IT security" />
            {/* <NavLink label="Files to loot" icon={<IconFile size={20} />} /> */}
            <CustomNavLink href="/notes" title="Notes" icon={<IconMarkdown size={20} />}>
                Notes
            </CustomNavLink>
            <CustomNavLink href="/blog" title="Blog" icon={<IconNews size={20} />}>
                Blog
            </CustomNavLink>
            <Divider label="// Other" />
            <CustomNavLink href="/world-map" title="World Map" icon={<IconWorld size={20} />}>
                World Map
            </CustomNavLink>
        </Navbar.Section>
    </>
)

const SideNav = () => (
    <Navbar width={{ base: 240 }} pos="sticky" top={0} p="sm" hiddenBreakpoint="sm" hidden={true}>
        <NavContent />
    </Navbar>
)

const TopNav: FC<{ isOpen: boolean; toggleIsOpen: () => void }> = ({ isOpen, toggleIsOpen }) => (
    <MediaQuery largerThan="sm" styles={{ display: "none" }}>
        <Container
            sx={t => ({
                backgroundColor: t.colors.dark[9],
                display: "flex",
                position: "fixed",
                width: "100%",
                height: 40,
                alignItems: "center",
                fontWeight: 900,
            })}
        >
            <Burger
                opened={isOpen}
                onClick={toggleIsOpen}
                size="sm"
                mr="xl"
                sx={t => ({ color: t.colors.gray[5] })}
            />
            <Flex align="flex-end">
                <Text c="white">Print3M</Text>
                <Text
                    sx={t => ({
                        color: t.colors.brand[4],
                        fontSize: 14,
                        whiteSpace: "nowrap",
                    })}
                >
                    {"'"}s hub
                </Text>
            </Flex>
        </Container>
    </MediaQuery>
)

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
            <Container p="sm" mih="100vh" w="100%" sx={{ overflow: "hidden" }}>
                <MediaQuery largerThan="sm" styles={{ display: "none" }}>
                    <Space h={75} />
                </MediaQuery>
                <MediaQuery smallerThan="sm" styles={{ display: "none" }}>
                    <Space h={35} />
                </MediaQuery>
                {children}
                <Footer height={20} ta="center" mt={100}>
                    <Text pt="xs" pb="xs">
                        Print3M&apos;s hub © {new Date().getFullYear()}
                    </Text>
                </Footer>
            </Container>
        </Flex>
    </>
)

export default Layout
