export const getPageTitle = (text: string) => `${text} | Print3M`

export const slugify = (input: string) =>
    input
        .toLowerCase()
        .replace(/[^\w\s-]/g, "") // Remove non-word characters
        .replace(/[\s]+/g, "-") // Replace spaces with hyphens
        .replace(/[-]+/g, "-") // Replace consecutive hyphens with a single hyphen
        .trim() // Trim leading and trailing whitespace

export const getDateStr = (date: Date) => date.toLocaleDateString("en-GB")

export const convertISOtoDateStr = (isoDate: string) => {
    const d = new Date(isoDate)

    return getDateStr(d)
}
