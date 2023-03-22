import { MantineThemeOverride } from "@mantine/core"

const theme: MantineThemeOverride = {
    headings: {
        fontWeight: 700,
        fontFamily: "'Noto Sans', sans-serif",
        sizes: {
            h1: {},
        },
    },
    fontFamily: "'Noto Sans', sans-serif",
    colors: {
        brand: [
            "#E3F2FD",
            "#BBDEFB",
            "#90CAF9",
            "#64B5F6",
            "#42A5F5",
            "#2196F3",
            "#1E88E5",
            "#1976D2",
            "#1565C0",
            "#0D47A1",
        ],
        dark: [
            // Default Mantine dark theme
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
    },
    primaryColor: "brand",
    primaryShade: 4,
    colorScheme: "dark",
    globalStyles: theme => ({
        a: {
            color: theme.colors.brand[4],
            textDecoration: "none",

            ":hover": {
                textDecoration: "underline",
            },
        },
    }),
}

export default theme
