import {
    Box,
    Collapse,
    ColorSwatch,
    Flex,
    Select,
    Space,
    Switch,
    Text,
    Tooltip,
    useMantineTheme,
} from "@mantine/core"
import { ComposableMap, Geographies, Geography, ZoomableGroup } from "react-simple-maps"
import { maps } from "./maps"
import { FC, useMemo, useState } from "react"
import { DataSet, MapKey, MapView } from "./types"
import { CountryCode, countries } from "./countries"

const geoUrl = "https://raw.githubusercontent.com/deldersveld/topojson/master/world-countries.json"

const selectData = Object.entries(maps)
    .sort()
    .map(([key, value]) => ({
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
                {data.members.sort().map(i => (
                    <Box key={`${i}${data.label}${data.color}`}>
                        {countries[i].flag || "🚫"} {countries[i].name}
                    </Box>
                ))}
            </Flex>
        </Collapse>
    </Box>
)

const Legend: FC<{ mapKey: MapKey; setMapKey: (v: MapKey) => void }> = ({ mapKey, setMapKey }) => {
    const [showCountries, setShowCountries] = useState(false)
    const map = useMemo(() => maps[mapKey], [mapKey])

    return (
        <Flex direction="column" gap="sm">
            <Select
                label="Map selection"
                data={selectData}
                onChange={v => setMapKey(v as MapKey)}
                defaultValue={mapKey}
            />
            <Switch
                checked={showCountries}
                onChange={v => setShowCountries(v.currentTarget.checked)}
                label="Show countries"
            />
            <Space h="xs" />
            <Flex direction="column" gap="sm" mih={500}>
                {map.dataSets.map(data => (
                    <LegendItem key={`${mapKey}${data.label}`} data={data} opened={showCountries} />
                ))}
            </Flex>
        </Flex>
    )
}

const CountryShape: FC<{ geo: any; map: MapView }> = ({ geo, map }) => {
    const t = useMantineTheme()
    const data = useMemo(() => countries[geo.id as CountryCode], [geo.id])

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

    if (!data) {
        /*
            Just skip these weird-fake countries which are not defined
            in our list of countries. 
        */
        return <></>
    }

    return (
        <Tooltip.Floating label={`${data.flag} ${data.name}`}>
            <Geography
                geography={geo}
                style={{
                    hover: {
                        fill: t.colors.dark[3],
                    },
                    default: {
                        fill: getFillColor(geo.id),
                        stroke: "gray",
                        strokeWidth: 0.22,
                    },
                }}
            />
        </Tooltip.Floating>
    )
}

const Map: FC<{ map: MapView }> = ({ map }) => {
    return (
        <ComposableMap>
            <ZoomableGroup maxZoom={6}>
                <Geographies geography={geoUrl}>
                    {({ geographies }) =>
                        geographies.map(geo => (
                            <CountryShape geo={geo} map={map} key={geo.rsmKey} />
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
            <Legend mapKey={mapKey} setMapKey={v => setMapKey(v)} />
        </>
    )
}

export default WorldMap
