import { serialize } from "next-mdx-remote/serialize"

export type MDXSource = Awaited<ReturnType<typeof serialize>>
