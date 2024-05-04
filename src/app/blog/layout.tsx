import BasicLayout from "@/components/BasicLayout/BasicLayout"
import { FC, PropsWithChildren } from "react"

const Layout: FC<PropsWithChildren> = ({ children }) => <BasicLayout>{children}</BasicLayout>

export default Layout
