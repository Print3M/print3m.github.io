import { Button, Group, Stack } from "@mantine/core"
import Link from "next/link"
import { GlobalData } from "@/config"
import { SocialIcons } from "../SocialIcons/SocialIcons"

const BlogButton = () => (
    <Button component={Link} title="Blog" href="/" variant="subtle">
        Blog
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
        <BlogButton />
        <SecuritreeButton />
        <Group>
            <SocialIcons />
        </Group>
    </Group>
)

export const MobileNavigation = () => (
    <Stack>
        <BlogButton />
        <SecuritreeButton />
        <Group justify="center">
            <SocialIcons />
        </Group>
    </Stack>
)
