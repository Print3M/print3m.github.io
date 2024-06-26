"use client"

import { Anchor, Image, TypographyStylesProvider } from "@mantine/core"
import { IconExternalLink } from "@tabler/icons-react"
import { MDXRemote } from "next-mdx-remote"
import Link from "next/link"
import Heading from "../Heading/Heading"
import { MDX } from "@/types"
import { FC, useState } from "react"
import classes from "./MDRenderer.module.css"
import ImagePreview from "../ImagePreview/ImagePreview"

interface Props {
    mdx: MDX
}

const MDRenderer: FC<Props> = ({ mdx }) => {
    const [imgSrc, setImgSrc] = useState<string | null>(null)

    return (
        <>
            <TypographyStylesProvider pt="xl" ta="justify">
                <MDXRemote
                    compiledSource={mdx}
                    scope=""
                    frontmatter={{}}
                    components={{
                        h1: props => <Heading order={1} text={props.children?.toString() || ""} />,
                        h2: props => <Heading order={2} text={props.children?.toString() || ""} />,
                        h3: props => <Heading order={3} text={props.children?.toString() || ""} />,
                        h4: props => <Heading order={4} text={props.children?.toString() || ""} />,
                        a: props => {
                            if (!props.href) return props.children

                            return (
                                <Anchor component={Link} href={props.href}>
                                    {props.children}
                                    {props.href.startsWith("http") && (
                                        <IconExternalLink
                                            size={12}
                                            style={{ transform: "translate(1px, -5px)" }}
                                        />
                                    )}
                                </Anchor>
                            )
                        },
                        figure: props => (
                            <figure {...props} style={{ margin: 0, paddingBottom: 20 }} />
                        ),
                        code: props => <code {...props} className={classes.code} />,
                        blockquote: props => (
                            <blockquote className={classes.blockquote}>{props.children}</blockquote>
                        ),
                        img: props => (
                            <Image
                                src={props.src}
                                alt={props.alt || ""}
                                onClick={() => setImgSrc(props.src || null)}
                                style={{ cursor: "pointer" }}
                            />
                        ),
                    }}
                />
            </TypographyStylesProvider>
            <ImagePreview src={imgSrc} onClose={() => setImgSrc(null)} />
        </>
    )
}

export default MDRenderer
