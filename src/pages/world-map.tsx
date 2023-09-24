import dynamic from "next/dynamic"

const WorldMap = dynamic(() => import("components/pages/WorldMap/index"), { ssr: false })

const WorldMapPage = () => <WorldMap />

export default WorldMapPage
