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
      "#7AD1DD",
      "#5FCCDB",
      "#44CADC",
      "#2AC9DE",
      "#1AC2D9",
      "#11B7CD",
      "#09ADC3",
      "#0E99AC",
      "#128797",
      "#147885",
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
  colorScheme: "dark",
  globalStyles: theme => ({
    a: {
      color: "#0079d6",
    },
  }),
}

export default theme
