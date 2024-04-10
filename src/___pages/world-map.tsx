import WorldMap from "@/components/WorldMap/WorldMap"
import { Title } from "@mantine/core"

const WorldMapPage = () => (
    <>
        <Title order={1} mb="md">
            World organizations map
        </Title>
        <WorldMap />
    </>
)

export default WorldMapPage
