import { Color } from "./styles"
import { MapView } from "./types"

const EU: MapView = {
    label: "EU",
    fullName: "European Union",
    dataSets: [
        {
            label: "Members",
            color: Color.RED_1,
            // prettier-ignore
            members: [
                "POL", "FRA", "GRC", "ESP", "DEU", "FIN", "SWE", "ITA", "HRV", "SVN",
                "CZE", "SVK", "BEL", "IRL", "PRT", "LUX", "NLD", "DNK", "AUT", "HUN",
                "ROU", "BGR", "EST", "LVA", "LTU", "CYP", "MLT", "GUF"
            ],
        },
        {
            label: "Former members",
            color: Color.ORANGE_1,
            members: ["GBR"],
        },
        {
            label: "Candidates",
            color: Color.GREEN_1,
            members: ["BIH", "TUR"],
        },
        {
            label: "Candidates negotiating",
            color: Color.GREEN_2,
            members: ["SRB", "UKR", "MDV", "MKD", "ALB", "MNE"],
        },
        {
            label: "Potential candidates",
            color: Color.YELLOW_1,
            members: ["CS-KM", "GEO"],
        },
    ],
}

const NATO: MapView = {
    label: "NATO",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.RED_1,
            // prettier-ignore
            members: [
                "POL", "FRA", "GRC", "ESP", "DEU", "FIN", "MKD", "ITA", "HRV", "SVN",
                "CZE", "SVK", "BEL", "IRL", "PRT", "LUX", "NLD", "DNK", "ISL", "HUN",
                "ROU", "BGR", "EST", "LVA", "LTU", "CYP", "MLT", "NOR", "USA", "GBR",
                "TUR", "MNE", "CAN",
            ],
        },
        {
            label: "Accession process",
            color: Color.GREEN_1,
            members: ["SWE", "BIH"],
        },
        {
            label: "Potential members",
            color: Color.GREEN_2,
            members: ["UKR", "GEO"],
        },
    ],
}

const CSTO: MapView = {
    label: "CSTO",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.RED_1,
            members: ["RUS", "BLR", "ARM", "KAZ", "TJK", "KGZ"],
        },
        {
            label: "Former members",
            color: Color.ORANGE_1,
            members: ["UZB", "GEO", "AZE"],
        },
        {
            label: "Observers",
            color: Color.GREEN_1,
            members: ["SRB"],
        },
    ],
}

const V4: MapView = {
    label: "V4",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.RED_1,
            members: ["POL", "CZE", "SVK", "HUN"],
        },
    ],
}

/*
    - BRICKS
    - EEA
    - OPEC
    - EFTA
    - EUCU

*/

export const maps = {
    EU,
    NATO,
    CSTO,
    V4,
}
