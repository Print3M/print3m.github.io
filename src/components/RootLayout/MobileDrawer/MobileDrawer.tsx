import { Drawer, Group, Stack } from "@mantine/core"
import Logo from "../Logo/Logo"
import { FC } from "react"
import { MobileNavigation } from "../Navigation/Navigation"

interface Props {
    opened: boolean
    onClose: () => void
}

const MobileDrawer: FC<Props> = ({ opened, onClose }) => (
    <Drawer opened={opened} onClose={onClose}>
        <Stack align="center">
            <Logo />
            <MobileNavigation />
        </Stack>
    </Drawer>
)

export default MobileDrawer
