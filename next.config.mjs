/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    output: "export",

    experimental: {
        optimizePackageImports: ["@mantine/core", "@mantine/hooks", "@tabler/icons-react"],
    },
}

export default nextConfig
