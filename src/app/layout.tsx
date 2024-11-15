import { Metadata } from "next"
import { FC, PropsWithChildren } from "react"
import { ColorSchemeScript, MantineProvider, createTheme } from "@mantine/core"
import "@mantine/core/styles/global.css"
import "@mantine/core/styles.css"

import { GlobalData } from "@/config"
import RootLayout from "@/components/RootLayout/RootLayout"

const title = "Print3M's Hub - IT security blog"
const description = "IT security research and programming: blog & notes."
const author = "Print3M"

export const metadata: Metadata = {
    metadataBase: new URL(GlobalData.url),
    title,
    description,
    authors: [{ name: author, url: GlobalData.url }],
    applicationName: "Print3M's Hub",
    keywords: [
        "IT",
        "security",
        "cybersecurity",
        "notes",
        "offensive security",
        "research",
        "blog",
        "cheat-sheet",
    ],
    twitter: {
        title,
        description,
        card: "summary",
        creator: GlobalData.xCreator,
        site: GlobalData.url,
    },
    openGraph: {
        title,
        locale: "en_US",
        determiner: "auto",
        type: "website",
        siteName: "Print3M's Blog",
        url: GlobalData.url,
    },
}

const theme = createTheme({
    /** Put your mantine theme override here */
    primaryShade: 7,
    primaryColor: "blue",
    cursorType: "pointer",
    colors: {
        dark: [
            "#C1C2C5",
            "#A6A7AB",
            "#909296",
            "#5c5f66",
            "#373A40",
            "#2C2E33",
            "#25262b",
            "#1A1B1E",
            "#141517",
            "#101113",
        ],
        gray: [
            "#f8f9fa",
            "#f1f3f5",
            "#e9ecef",
            "#dee2e6",
            "#ced4da",
            "#adb5bd",
            "#868e96",
            "#495057",
            "#343a40",
            "#212529",
        ],
    },
})

const colorSchema = "dark"

const Layout: FC<PropsWithChildren> = async ({ children }) => (
    <html lang="en" data-mantine-color-scheme={colorSchema}>
        <head>
            <ColorSchemeScript forceColorScheme={colorSchema} />
        </head>
        <body style={{ backgroundColor: "#242424" }}>
            <MantineProvider forceColorScheme={colorSchema} theme={theme}>
                <RootLayout>{children}</RootLayout>
            </MantineProvider>
        </body>
    </html>
)

export default Layout
