import { FC } from "react"
import classes from "./Navigation.module.css"
import { ActionIcon, Button, Group, Stack } from "@mantine/core"
import Link from "next/link"
import { GlobalData } from "@/config"
import { IconBrandGithub } from "@tabler/icons-react"
import Logo from "../Logo/Logo"

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
        href={GlobalData.securitreeUrl}
        variant="subtle"
    >
        SecuriTree
    </Button>
)

const GitHubIcon = () => (
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
)

export const DesktopNavigation = () => (
    <Group>
        <HomeButton />
        <BlogButton />
        <NotesButton />
        <SecuritreeButton />
        <Group>
            <GitHubIcon />
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
            <GitHubIcon />
        </Group>
    </Stack>
)
