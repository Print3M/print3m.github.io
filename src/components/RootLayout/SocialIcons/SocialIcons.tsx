import { GlobalData } from "@/config"
import { ActionIcon } from "@mantine/core"
import { IconBrandGithub, IconBrandX } from "@tabler/icons-react"
import Link from "next/link"

const GitHubIcon = () => (
    <ActionIcon
        component={Link}
        href={GlobalData.githubUrl}
        title="Print3M GitHub"
        variant="subtle"
        w={28}
        h={28}
    >
        <IconBrandGithub color="white" size={23} />
    </ActionIcon>
)

const XIcon = () => (
    <ActionIcon
        component={Link}
        href={GlobalData.xUrl}
        title="Print3M X Profile"
        variant="subtle"
        w={28}
        h={28}
    >
        <IconBrandX color="white" size={23} />
    </ActionIcon>
)

export const SocialIcons = () => (
    <>
        <GitHubIcon />
        <XIcon />
    </>
)
