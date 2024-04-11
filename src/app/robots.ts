import { GlobalData } from "@/config"
import { MetadataRoute } from "next"

const robots = (): MetadataRoute.Robots => ({
    rules: {
        userAgent: "*",
        allow: "/",
    },
    sitemap: `${GlobalData.url}/sitemap.xml`,
})

export default robots
