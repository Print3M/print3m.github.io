import { createGetInitialProps } from "@mantine/next"
import Document, { Head, Html, Main, NextScript } from "next/document"

const getInitialProps = createGetInitialProps()

export default class _Document extends Document {
    static getInitialProps = getInitialProps

    render() {
        return (
            <Html>
                <Head>
                    <meta name="description" content="IT security, low-level, red-team, Linux, Windows, programming - personal notes, cheat-sheets and blog." />
                    <meta
                        name="google-site-verification"
                        content="PyNPHvUlr8W_Gw-y2349IW1mlsKlfSi6qHeRw2Jx4Cw"
                    />
                </Head>
                <body>
                    <Main />
                    <NextScript />
                </body>
            </Html>
        )
    }
}
