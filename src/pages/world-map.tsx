import { Title } from "@mantine/core"
import WorldMap from "components/pages/WorldMap/WorldMap"

const WorldMapPage = () => (
    <>
        <Title order={1} mb="md">
            World organizations map
        </Title>
        <WorldMap />
    </>
)

export default WorldMapPage
