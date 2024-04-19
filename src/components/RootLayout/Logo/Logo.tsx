import { Box, Flex } from "@mantine/core"

const Logo = () => (
    <Flex align="flex-end" fw="bolder">
        <Box c="white" fz={26}>
            Print3M
        </Box>
        <Box c="var(--mantine-primary-color-filled)" fz={16} pb={6} fw="inherit">
            {"'"}s Hub
        </Box>
    </Flex>
)

export default Logo
