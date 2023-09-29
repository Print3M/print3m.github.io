import {
    Box,
    Collapse,
    ColorSwatch,
    Flex,
    Select,
    Space,
    Switch,
    Text,
    useMantineTheme,
} from "@mantine/core"
import { ComposableMap, Geographies, Geography, ZoomableGroup } from "react-simple-maps"
import { maps } from "./maps"
import { FC, useState } from "react"
import { DataSet, MapKey, MapView } from "./types"
import { CountryCode, countries } from "./countries"

const geoUrl = "https://raw.githubusercontent.com/deldersveld/topojson/master/world-countries.json"

const selectData = Object.entries(maps).map(([key, value]) => ({
    value: key,
    label: value.label,
}))

const LegendItem: FC<{ data: DataSet; opened: boolean }> = ({ data, opened }) => (
    <Box>
        <Flex gap={10} align="center" key={`${data.label}${data.color}`}>
            <ColorSwatch color={data.color} size={25} />
            <Text fw="bold">{data.label}</Text>
        </Flex>

        <Collapse in={opened}>
            <Flex gap="xs" fz="sm" mt={10} mb={4} pl={30} wrap="wrap">
                {data.members.map(i => (
                    <Box key={i}>
                        {countries[i].flag || "🚫"} {countries[i].name}
                    </Box>
                ))}
            </Flex>
        </Collapse>
    </Box>
)

const Legend: FC<{ map: MapView; setMapKey: (v: MapKey) => void }> = ({ map, setMapKey }) => {
    const [showCountries, setShowCountries] = useState(false)

    return (
        <Flex direction="column" gap="sm">
            <Select
                label="Map selection"
                data={selectData}
                onChange={v => setMapKey(v as MapKey)}
                defaultValue={"NATO"}
            />
            <Switch
                checked={showCountries}
                onChange={v => setShowCountries(v.currentTarget.checked)}
                label="Show countries"
            />
            <Space h="xs" />
            <Flex direction="column" gap="sm" mih={500}>
                {map.dataSets.map(data => (
                    <LegendItem key={data.label} data={data} opened={showCountries} />
                ))}
            </Flex>
        </Flex>
    )
}

const Map: FC<{ map: MapView }> = ({ map }) => {
    const t = useMantineTheme()

    const getFillColor = (countryCode: CountryCode) => {
        /*
            Find a set within the current map with the `countryCode` included.
            Return the color of that set.
        */
        for (const set of map.dataSets) {
            if (set.members.includes(countryCode)) {
                return set.color
            }
        }

        // Default color
        return t.colors.brand[1]
    }

    return (
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
    )
}

const WorldMap = () => {
    const [mapKey, setMapKey] = useState<MapKey>("CSTO")

    return (
        <>
            <Map map={maps[mapKey]} />
            <Legend map={maps[mapKey]} setMapKey={v => setMapKey(v)} />
        </>
    )
}

export default WorldMap
