import { Center, Container, Drawer, Flex, Stack } from "@mantine/core"
import { FC, useEffect, useState } from "react"
import { Divider, Navbar, NavLink, Space, Text } from "@mantine/core"
import { IconBrandGithub, IconHome, IconMarkdown, IconNews } from "@tabler/icons-react"
import { Burger, MediaQuery, useMantineTheme } from "@mantine/core"
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
                <Text c="#fff">Print3M</Text>
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
            {/* <NavLink label="Checklists" icon={<IconList size={20} />} /> */}
            <CustomNavLink href="/notes" title="Notes" icon={<IconMarkdown size={20} />}>
                Notes
            </CustomNavLink>
            <CustomNavLink href="/blog" title="Blog" icon={<IconNews size={20} />}>
                Blog
            </CustomNavLink>
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
        <Container>
            <SideNav />
            <Container p="sm" mih="100vh" w="100%" pb={100}>
                <MediaQuery largerThan="sm" styles={{ display: "none" }}>
                    <Space h={50} />
                </MediaQuery>
                <MediaQuery smallerThan="sm" styles={{ display: "none" }}>
                    <Space h={35} />
                </MediaQuery>
                {children}
            </Container>
        </Container>
    </>
)

export default Layout
