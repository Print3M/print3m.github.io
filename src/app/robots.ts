import { GlobalData } from "@/config"
import { MetadataRoute } from "next"

export const dynamic = "force-static"

const robots = (): MetadataRoute.Robots => ({
    rules: {
        userAgent: "*",
        allow: "/",
    },
    sitemap: `${GlobalData.url}/sitemap.xml`,
})

export default robots
