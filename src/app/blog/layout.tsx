import BasicLayout from "@/components/BasicLayout"
import { FC, PropsWithChildren } from "react"

const Layout: FC<PropsWithChildren> = ({ children }) => <BasicLayout>{children}</BasicLayout>

export default Layout
