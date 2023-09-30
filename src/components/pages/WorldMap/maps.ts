import { CountryCode as CC } from "./countries"
import { Color } from "./styles"
import { MapView } from "./types"

const EU: MapView = {
    label: "EU",
    fullName: "European Union",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.POLAND, CC.FRANCE, CC.GREECE, CC.SPAIN, CC.GERMANY, CC.FINLAND, CC.SWEDEN,
                CC.ITALY, CC.CROATIA, CC.SLOVENIA, CC.SLOVAKIA, CC.CZECHIA, CC.BELGIUM,
                CC.IRELAND, CC.PORTUGAL, CC.NETHERLANDS, CC.DENMARK, CC.AUSTRIA, CC.HUNGARY,
                CC.ROMANIA, CC.BULGARIA, CC.ESTONIA, CC.LATVIA, CC.LITHUANIA, CC.CYPRUS, CC.MALTA,
                CC.FRENCH_GUIANA
            ],
        },
        {
            label: "Former members",
            color: Color.ORANGE_1,
            members: [CC.UNITED_KINGDOM],
        },
        {
            label: "Candidates",
            color: Color.BLUE_1,
            // prettier-ignore
            members: [
                CC.SERBIA, CC.UKRAINE, CC.MOLDOVA, CC.MACEDONIA, CC.ALBANIA, CC.MONTENEGRO,
                CC.BOSNIA_AND_HERZEGOVINA, CC.TURKEY
            ],
        },
        {
            label: "Potential candidates",
            color: Color.YELLOW_1,
            members: [CC.KOSOVO, CC.GEORGIA],
        },
    ],
}

const NATO: MapView = {
    label: "NATO",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.POLAND, CC.FRANCE, CC.GREECE, CC.SPAIN, CC.GERMANY, CC.FINLAND, CC.NORWAY,
                CC.ITALY, CC.CROATIA, CC.SLOVENIA, CC.SLOVAKIA, CC.CZECHIA, CC.BELGIUM,
                CC.IRELAND, CC.PORTUGAL, CC.NETHERLANDS, CC.DENMARK, CC.CANADA, CC.HUNGARY,
                CC.ROMANIA, CC.BULGARIA, CC.ESTONIA, CC.LATVIA, CC.LITHUANIA, CC.CYPRUS, CC.MALTA,
                CC.MONTENEGRO, CC.TURKEY, CC.ICELAND, CC.UNITED_KINGDOM, CC.MACEDONIA,
                CC.UNITED_STATES
            ],
        },
        {
            label: "Candidates",
            color: Color.BLUE_1,
            members: [CC.SWEDEN, CC.BOSNIA_AND_HERZEGOVINA],
        },
        {
            label: "Potential candidates",
            color: Color.YELLOW_1,
            members: [CC.UKRAINE, CC.GEORGIA],
        },
    ],
}

const CSTO: MapView = {
    label: "CSTO",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.RUSSIA, CC.BULGARIA, CC.ARMENIA, CC.KAZAKHSTAN, CC.TAJIKISTAN, CC.KYRGYZSTAN
            ],
        },
        {
            label: "Former members",
            color: Color.ORANGE_1,
            members: [CC.UZBEKISTAN, CC.GEORGIA, CC.AZERBAIJAN],
        },
        {
            label: "Observers",
            color: Color.BLUE_1,
            members: [CC.SERBIA],
        },
    ],
}

const V4: MapView = {
    label: "V4",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            members: [CC.POLAND, CC.CZECHIA, CC.SLOVAKIA, CC.HUNGARY],
        },
    ],
}

const BRICS: MapView = {
    label: "BRICS",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.BRAZIL, CC.EGYPT, CC.ETHIOPIA, CC.RUSSIA, CC.INDONESIA, CC.CHINA,
                CC.SAUDI_ARABIA, CC.UNITED_ARAB_EMIRATES, CC.IRAN, CC.ARGENTINA
            ],
        },
        {
            label: "Candidates",
            color: Color.BLUE_1,
            // prettier-ignore
            members: [
                CC.ALGERIA, CC.BAHRAIN, CC.BANGLADESH, CC.BELARUS, CC.BOLIVIA, CC.CUBA, CC.KUWAIT,
                CC.HONDURAS, CC.KAZAKHSTAN, CC.PALESTINE, CC.SENEGAL, CC.THAILAND, CC.VENEZUELA,
                CC.VIETNAM
            ],
        },
    ],
}

const SCHENGEN: MapView = {
    label: "Schengen zone",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.GERMANY, CC.AUSTRIA, CC.BELGIUM, CC.CROATIA, CC.CZECHIA, CC.DENMARK, CC.ESTONIA,
                CC.FINLAND, CC.GREECE, CC.HUNGARY, CC.ICELAND, CC.ITALY, CC.LATVIA,
                CC.LIECHTENSTEIN, CC.LITHUANIA, CC.LUXEMBOURG, CC.MALTA, CC.NETHERLANDS, CC.NORWAY,
                CC.POLAND, CC.PORTUGAL, CC.SLOVAKIA, CC.SLOVENIA, CC.SPAIN, CC.SWEDEN,
                CC.SWITZERLAND, CC.FRANCE
            ],
        },
        {
            label: "Candidates",
            color: Color.BLUE_1,
            members: [CC.BULGARIA, CC.ROMANIA, CC.CYPRUS],
        },
    ],
}

const OPEC: MapView = {
    label: "OPEC",
    fullName: "Organization of the Petroleum Exporting Countries",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.ALGERIA, CC.ANGOLA, CC.CONGO_BRAZZAVILLE, CC.EQUATORIAL_GUINEA, CC.GABON,
                CC.IRAN, CC.IRAQ, CC.KUWAIT, CC.LIBYA, CC.NIGERIA, CC.SAUDI_ARABIA,
                CC.UNITED_STATES, CC.VENEZUELA
            ],
        },
        {
            label: "Former members",
            color: Color.ORANGE_1,
            members: [CC.ECUADOR, CC.INDONESIA, CC.QATAR],
        },
    ],
}

const ARAB_LEAGUE: MapView = {
    label: "Arab League",
    fullName: "League of Arab States",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            // prettier-ignore
            members: [
                CC.ALGERIA, CC.BAHRAIN, CC.COMOROS, CC.DJIBOUTI, CC.EGYPT, CC.IRAQ, CC.JORDAN,
                CC.KUWAIT, CC.LEBANON, CC.LIBYA, CC.MAURITANIA, CC.MOROCCO, CC.OMAN, CC.PALESTINE,
                CC.QATAR, CC.SAUDI_ARABIA, CC.SOMALIA, CC.SUDAN, CC.SYRIA, CC.TUNISIA, CC.YEMEN,
                CC.UNITED_ARAB_EMIRATES,
            ],
        },
    ],
}

const OPEN_BALKAN: MapView = {
    label: "Open Balkan",
    fullName: "",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            members: [CC.MACEDONIA, CC.SERBIA, CC.ALBANIA],
        },
        {
            label: "Potential candidates",
            color: Color.BLUE_1,
            members: [CC.MONTENEGRO, CC.BOSNIA_AND_HERZEGOVINA, CC.KOSOVO],
        },
    ],
}

const EFTA: MapView = {
    label: "EFTA",
    fullName: "European Free Trade Association",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            members: [CC.NORWAY, CC.ICELAND, CC.SWITZERLAND, CC.LIECHTENSTEIN],
        },
        {
            label: "Former members",
            color: Color.ORANGE_1,
            // prettier-ignore
            members: [
                CC.AUSTRIA, CC.DENMARK, CC.FINLAND, CC.PORTUGAL, CC.SWEDEN, CC.UNITED_KINGDOM,
            ],
        },
    ],
}

const EEU: MapView = {
    label: "EEU",
    fullName: "Eurasian Economic Union",
    dataSets: [
        {
            label: "Members",
            color: Color.GREEN_1,
            members: [CC.ARMENIA, CC.BELARUS, CC.KAZAKHSTAN, CC.KYRGYZSTAN, CC.RUSSIA],
        },
    ],
}

/*
    - EEA
    - EUCU
    - AFRICAN UNION
*/

export const maps = {
    EU,
    NATO,
    CSTO,
    V4,
    BRICS,
    SCHENGEN,
    OPEC,
    ARAB_LEAGUE,
    OPEN_BALKAN,
    EFTA,
    EEU,
}
