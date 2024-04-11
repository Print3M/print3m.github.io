import { Box } from "@mantine/core"
import { FC, PropsWithChildren } from "react"

const BasicLayout: FC<PropsWithChildren> = ({ children }) => (
    <Box maw={700} mx="auto" pt="lg">
        {children}
    </Box>
)

export default BasicLayout
