/*
    - international organizations
    - world conflicts
*/
import { Box, ColorSwatch, Container, Flex, Select, Text, useMantineTheme } from "@mantine/core"
import { ComposableMap, Geographies, Geography, ZoomableGroup } from "react-simple-maps"
import { maps } from "./maps"
import { useState } from "react"
import { CountryCode, MapKey } from "./types"

const geoUrl = "https://raw.githubusercontent.com/deldersveld/topojson/master/world-countries.json"

const WorldMap = () => {
    const [map, setMap] = useState<MapKey>("CSTO")
    const t = useMantineTheme()

    const getFillColor = (countryCode: CountryCode) => {
        /*
            Find a set within the current map with the `countryCode` included.
            Return the color of that set.
        */
        console.log(map)

        for (const set of maps[map].dataSets) {
            if (set.members.includes(countryCode)) {
                return set.color
            }
        }

        // Default color
        return t.colors.brand[3]
    }

    return (
        <>
            <ComposableMap>
                <ZoomableGroup maxZoom={6}>
                    <Geographies geography={geoUrl}>
                        {({ geographies }) =>
                            geographies.map(geo => (
                                <Geography
                                    key={geo.rsmKey}
                                    geography={geo}
                                    fill={getFillColor(geo.id)}
                                    stroke="gray"
                                    strokeWidth={0.22}
                                    onMouseOver={() => console.log(geo.id, geo.rsmKey, geo.name)}
                                />
                            ))
                        }
                    </Geographies>
                </ZoomableGroup>
            </ComposableMap>
            <Select
                label="Select map"
                data={Object.keys(maps)}
                onChange={v => setMap(v as MapKey)}
                defaultValue={"NATO"}
            />
            <Container mt="lg">
                {maps[map].dataSets.map(set => (
                    <Flex gap={10} align="center" key={`${set.label}${set.color}`}>
                        <ColorSwatch color={set.color} size={20} />
                        <Text>{set.label}</Text>
                    </Flex>
                ))}
            </Container>
        </>
    )
}

export default WorldMap
