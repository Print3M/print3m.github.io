import { Box, Flex } from "@mantine/core"
import Link from "next/link"

const Logo = () => (
    <Link href="/" style={{ textDecoration: "none" }}>
        <Flex align="flex-end" fw="bolder">
            <Box c="white" fz={26}>
                Print3M
            </Box>
            <Box c="var(--mantine-primary-color-filled)" fz={16} pb={6} fw="inherit">
                {"'"}s Hub
            </Box>
        </Flex>
    </Link>
)

export default Logo
