import { Button, Group, Stack } from "@mantine/core"
import Link from "next/link"
import { GlobalData } from "@/config"
import { SocialIcons } from "../SocialIcons/SocialIcons"

const HomeButton = () => (
    <Button component={Link} title="Home" href="/" variant="subtle">
        Home
    </Button>
)

const BlogButton = () => (
    <Button component={Link} title="Blog" href="/blog" variant="subtle">
        Blog
    </Button>
)

const NotesButton = () => (
    <Button component={Link} title="Notes & cheat-sheets" href="/notes" variant="subtle">
        Notes
    </Button>
)

const SecuritreeButton = () => (
    <Button
        component={Link}
        color="orange"
        title="SecuriTree.xyz"
        href={GlobalData.sectubeUrl}
        variant="subtle"
    >
        SecTube
    </Button>
)

export const DesktopNavigation = () => (
    <Group>
        <HomeButton />
        <BlogButton />
        <NotesButton />
        <SecuritreeButton />
        <Group>
            <SocialIcons />
        </Group>
    </Group>
)

export const MobileNavigation = () => (
    <Stack>
        <HomeButton />
        <BlogButton />
        <NotesButton />
        <SecuritreeButton />
        <Group justify="center">
            <SocialIcons />
        </Group>
    </Stack>
)
