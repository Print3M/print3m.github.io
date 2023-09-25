/*
    Countries Alpha-3 codes:
    https://www.iban.com/country-codes
*/

export enum CountryCode {
    AFGHANISTAN = "AFG",
    ALAND_ISLANDS = "ALA",
    ALBANIA = "ALB",
    ALGERIA = "DZA",
    AMERICAN_SAMOA = "ASM",
    ANDORRA = "AND",
    ANGOLA = "AGO",
    ANGUILLA = "AIA",
    ANTARCTICA = "ATA",
    ANTIGUA_AND_BARBUDA = "ATG",
    ARGENTINA = "ARG",
    ARMENIA = "ARM",
    ARUBA = "ABW",
    AUSTRALIA = "AUS",
    AUSTRIA = "AUT",
    AZERBAIJAN = "AZE",
    BAHAMAS = "BHS",
    BAHRAIN = "BHR",
    BANGLADESH = "BGD",
    BARBADOS = "BRB",
    BELARUS = "BLR",
    BELGIUM = "BEL",
    BELIZE = "BLZ",
    BENIN = "BEN",
    BERMUDA = "BMU",
    BHUTAN = "BTN",
    BOLIVIA = "BOL",
    BONAIRE = "BES",
    BOSNIA_AND_HERZEGOVINA = "BIH",
    BOTSWANA = "BWA",
    BOUVET_ISLAND = "BVT",
    BRAZIL = "BRA",
    BRITISH_INDIAN_OCEAN_TERRITORY = "IOT",
    BRUNEI_DARUSSALAM = "BRN",
    BULGARIA = "BGR",
    BURKINA_FASO = "BFA",
    BURUNDI = "BDI",
    CAMBODIA = "KHM",
    CAMEROON = "CMR",
    CANADA = "CAN",
    CAPE_VERDE = "CPV",
    CAYMAN_ISLANDS = "CYM",
    CENTRAL_AFRICAN_REPUBLIC = "CAF",
    KOSOVO = "CS-KM",
    CHAD = "TCD",
    CHILE = "CHL",
    CHINA = "CHN",
    CHRISTMAS_ISLAND = "CXR",
    COCOS_ISLANDS = "CCK",
    COLOMBIA = "COL",
    COMOROS = "COM",
    CONGO_KINSHASA = "COD",
    CONGO_BRAZZAVILLE = "COG",
    COOK_ISLANDS = "COK",
    COSTA_RICA = "CRI",
    COTE_D_IVOIRE = "CIV",
    CROATIA = "HRV",
    CUBA = "CUB",
    CURACAO = "CUW",
    CYPRUS = "CYP",
    CZECHIA = "CZE",
    DENMARK = "DNK",
    DJIBOUTI = "DJI",
    DOMINICA = "DMA",
    DOMINICAN_REPUBLIC = "DOM",
    ECUADOR = "ECU",
    EGYPT = "EGY",
    EL_SALVADOR = "SLV",
    EQUATORIAL_GUINEA = "GNQ",
    ERITREA = "ERI",
    ESTONIA = "EST",
    ETHIOPIA = "ETH",
    FALKLAND_ISLANDS = "FLK",
    FAROE_ISLANDS = "FRO",
    FIJI = "FJI",
    FINLAND = "FIN",
    FRANCE = "FRA",
    FRENCH_GUIANA = "GUF",
    FRENCH_POLYNESIA = "PYF",
    FRENCH_SOUTHERN_TERRITORIES = "ATF",
    GABON = "GAB",
    GAMBIA = "GMB",
    GEORGIA = "GEO",
    GERMANY = "DEU",
    GHANA = "GHA",
    GIBRALTAR = "GIB",
    GREECE = "GRC",
    GREENLAND = "GRL",
    GRENADA = "GRD",
    GUADELOUPE = "GLP",
    GUAM = "GUM",
    GUATEMALA = "GTM",
    GUERNSEY = "GGY",
    GUINEA = "GIN",
    GUINEA_BISSAU = "GNB",
    GUYANA = "GUY",
    HAITI = "HTI",
    HEARD_ISLAND_AND_MCDONALD_ISLANDS = "HMD",
    VATICAN = "VAT",
    HONDURAS = "HND",
    HONG_KONG = "HKG",
    HUNGARY = "HUN",
    ICELAND = "ISL",
    INDIA = "IND",
    INDONESIA = "IDN",
    IRAN = "IRN",
    IRAQ = "IRQ",
    IRELAND = "IRL",
    ISLE_OF_MAN = "IMN",
    ISRAEL = "ISR",
    ITALY = "ITA",
    JAMAICA = "JAM",
    JAPAN = "JPN",
    JERSEY = "JEY",
    JORDAN = "JOR",
    KAZAKHSTAN = "KAZ",
    KENYA = "KEN",
    KIRIBATI = "KIR",
    NORTH_KOREA = "PRK",
    SOUTH_KOREA = "KOR",
    KUWAIT = "KWT",
    KYRGYZSTAN = "KGZ",
    LAOS = "LAO",
    LATVIA = "LVA",
    LEBANON = "LBN",
    LESOTHO = "LSO",
    LIBERIA = "LBR",
    LIBYA = "LBY",
    LIECHTENSTEIN = "LIE",
    LITHUANIA = "LTU",
    LUXEMBOURG = "LUX",
    MACAO = "MAC",
    MACEDONIA = "MKD",
    MADAGASCAR = "MDG",
    MALAWI = "MWI",
    MALAYSIA = "MYS",
    MALDIVES = "MDV",
    MALI = "MLI",
    MALTA = "MLT",
    MARSHALL_ISLANDS = "MHL",
    MARTINIQUE = "MTQ",
    MAURITANIA = "MRT",
    MAURITIUS = "MUS",
    MAYOTTE = "MYT",
    MEXICO = "MEX",
    MICRONESIA = "FSM",
    MOLDOVA = "MDA",
    MONACO = "MCO",
    MONGOLIA = "MNG",
    MONTENEGRO = "MNE",
    MONTSERRAT = "MSR",
    MOROCCO = "MAR",
    MOZAMBIQUE = "MOZ",
    MYANMAR = "MMR",
    NAMIBIA = "NAM",
    NAURU = "NRU",
    NEPAL = "NPL",
    NETHERLANDS = "NLD",
    NEW_CALEDONIA = "NCL",
    NEW_ZEALAND = "NZL",
    NICARAGUA = "NIC",
    NIGER = "NER",
    NIGERIA = "NGA",
    NIUE = "NIU",
    NORFOLK_ISLAND = "NFK",
    NORTHERN_MARIANA_ISLANDS = "MNP",
    NORWAY = "NOR",
    OMAN = "OMN",
    PAKISTAN = "PAK",
    PALAU = "PLW",
    PALESTINE = "PSE",
    PANAMA = "PAN",
    PAPUA_NEW_GUINEA = "PNG",
    PARAGUAY = "PRY",
    PERU = "PER",
    PHILIPPINES = "PHL",
    PITCAIRN = "PCN",
    POLAND = "POL",
    PORTUGAL = "PRT",
    PUERTO_RICO = "PRI",
    QATAR = "QAT",
    RÉUNION = "REU",
    ROMANIA = "ROU",
    RUSSIA = "RUS",
    RWANDA = "RWA",
    SAINT_BARTHELEMY = "BLM",
    SAINT_HELENA = "SHN",
    SAINT_KITTS_AND_NEVIS = "KNA",
    SAINT_LUCIA = "LCA",
    SAINT_MARTIN = "MAF",
    SAINT_PIERRE_AND_MIQUELON = "SPM",
    SAINT_VINCENT_AND_THE_GRENADINES = "VCT",
    SAMOA = "WSM",
    SAN_MARINO = "SMR",
    SAO_TOME_AND_PRINCIPE = "STP",
    SAUDI_ARABIA = "SAU",
    SENEGAL = "SEN",
    SERBIA = "SRB",
    SEYCHELLES = "SYC",
    SIERRA_LEONE = "SLE",
    SINGAPORE = "SGP",
    SINT_MAARTEN = "SXM",
    SLOVAKIA = "SVK",
    SLOVENIA = "SVN",
    SOLOMON_ISLANDS = "SLB",
    SOMALIA = "SOM",
    SOUTH_AFRICA = "ZAF",
    SOUTH_GEORGIA_AND_THE_SOUTH_SANDWICH_ISLANDS = "SGS",
    SOUTH_SUDAN = "SSD",
    SPAIN = "ESP",
    SRI_LANKA = "LKA",
    SUDAN = "SDN",
    SURINAME = "SUR",
    SVALBARD_AND_JAN_MAYEN = "SJM",
    SWAZILAND = "SWZ",
    SWEDEN = "SWE",
    SWITZERLAND = "CHE",
    SYRIA = "SYR",
    TAIWAN = "TWN",
    TAJIKISTAN = "TJK",
    TANZANIA = "TZA",
    THAILAND = "THA",
    TIMOR_LESTE = "TLS",
    TOGO = "TGO",
    TOKELAU = "TKL",
    TONGA = "TON",
    TRINIDAD_AND_TOBAGO = "TTO",
    TUNISIA = "TUN",
    TURKEY = "TUR",
    TURKMENISTAN = "TKM",
    TURKS_AND_CAICOS_ISLANDS = "TCA",
    TUVALU = "TUV",
    UGANDA = "UGA",
    UKRAINE = "UKR",
    UNITED_ARAB_EMIRATES = "ARE",
    UNITED_KINGDOM = "GBR",
    UNITED_STATES = "USA",
    UNITED_STATES_MINOR_OUTLYING_ISLANDS = "UMI",
    URUGUAY = "URY",
    UZBEKISTAN = "UZB",
    VANUATU = "VUT",
    VENEZUELA = "VEN",
    VIETNAM = "VNM",
    BRITISH_VIRGIN_ISLANDS = "VGB",
    VIRGIN_ISLANDS = "VIR",
    WALLIS_AND_FUTUNA = "WLF",
    WESTERN_SAHARA = "ESH",
    YEMEN = "YEM",
    ZAMBIA = "ZMB",
    ZIMBABWE = "ZWE",
}

const CC = CountryCode

export const countries = {
    [CC.AFGHANISTAN]: { code: CC.AFGHANISTAN, name: "Afghanistan" },
    [CC.ALAND_ISLANDS]: { code: CC.ALAND_ISLANDS, name: "Åland Islands" },
    [CC.ALBANIA]: { code: CC.ALBANIA, name: "Albania" },
    [CC.ALGERIA]: { code: CC.ALGERIA, name: "Algeria" },
    [CC.AMERICAN_SAMOA]: { code: CC.AMERICAN_SAMOA, name: "American Samoa" },
    [CC.ANDORRA]: { code: CC.ANDORRA, name: "Andorra" },
    [CC.ANGOLA]: { code: CC.ANGOLA, name: "Angola" },
    [CC.ANGUILLA]: { code: CC.ANGUILLA, name: "Anguilla" },
    [CC.ANTARCTICA]: { code: CC.ANTARCTICA, name: "Antarctica" },
    [CC.ANTIGUA_AND_BARBUDA]: { code: CC.ANTIGUA_AND_BARBUDA, name: "Antigua and Barbuda" },
    [CC.ARGENTINA]: { code: CC.ARGENTINA, name: "Argentina" },
    [CC.ARMENIA]: { code: CC.ARMENIA, name: "Armenia" },
    [CC.ARUBA]: { code: CC.ARUBA, name: "Aruba" },
    [CC.AUSTRALIA]: { code: CC.AUSTRALIA, name: "Australia" },
    [CC.AUSTRIA]: { code: CC.AUSTRIA, name: "Austria" },
    [CC.AZERBAIJAN]: { code: CC.AZERBAIJAN, name: "Azerbaijan" },
    [CC.BAHAMAS]: { code: CC.BAHAMAS, name: "Bahamas" },
    [CC.BAHRAIN]: { code: CC.BAHRAIN, name: "Bahrain" },
    [CC.BANGLADESH]: { code: CC.BANGLADESH, name: "Bangladesh" },
    [CC.BARBADOS]: { code: CC.BARBADOS, name: "Barbados" },
    [CC.BELARUS]: { code: CC.BELARUS, name: "Belarus" },
    [CC.BELGIUM]: { code: CC.BELGIUM, name: "Belgium" },
    [CC.BELIZE]: { code: CC.BELIZE, name: "Belize" },
    [CC.BENIN]: { code: CC.BENIN, name: "Benin" },
    [CC.BERMUDA]: { code: CC.BERMUDA, name: "Bermuda" },
    [CC.BHUTAN]: { code: CC.BHUTAN, name: "Bhutan" },
    [CC.BOLIVIA]: { code: CC.BOLIVIA, name: "Bolivia, Plurinational State of" },
    [CC.BONAIRE]: { code: CC.BONAIRE, name: "Bonaire, Sint Eustatius and Saba" },
    [CC.BOSNIA_AND_HERZEGOVINA]: {
        code: CC.BOSNIA_AND_HERZEGOVINA,
        name: "Bosnia and Herzegovina",
    },
    [CC.BOTSWANA]: { code: CC.BOTSWANA, name: "Botswana" },
    [CC.BOUVET_ISLAND]: { code: CC.BOUVET_ISLAND, name: "Bouvet Island" },
    [CC.BRAZIL]: { code: CC.BRAZIL, name: "Brazil" },
    [CC.BRITISH_INDIAN_OCEAN_TERRITORY]: {
        code: CC.BRITISH_INDIAN_OCEAN_TERRITORY,
        name: "British Indian Ocean Territory",
    },
    [CC.BRUNEI_DARUSSALAM]: { code: CC.BRUNEI_DARUSSALAM, name: "Brunei Darussalam" },
    [CC.BULGARIA]: { code: CC.BULGARIA, name: "Bulgaria" },
    [CC.BURKINA_FASO]: { code: CC.BURKINA_FASO, name: "Burkina Faso" },
    [CC.BURUNDI]: { code: CC.BURUNDI, name: "Burundi" },
    [CC.CAMBODIA]: { code: CC.CAMBODIA, name: "Cambodia" },
    [CC.CAMEROON]: { code: CC.CAMEROON, name: "Cameroon" },
    [CC.CANADA]: { code: CC.CANADA, name: "Canada" },
    [CC.CAPE_VERDE]: { code: CC.CAPE_VERDE, name: "Cape Verde" },
    [CC.CAYMAN_ISLANDS]: { code: CC.CAYMAN_ISLANDS, name: "Cayman Islands" },
    [CC.CENTRAL_AFRICAN_REPUBLIC]: {
        code: CC.CENTRAL_AFRICAN_REPUBLIC,
        name: "Central African Republic",
    },
    [CC.KOSOVO]: { code: CC.KOSOVO, name: "Kosovo" },
    [CC.CHAD]: { code: CC.CHAD, name: "Chad" },
    [CC.CHILE]: { code: CC.CHILE, name: "Chile" },
    [CC.CHINA]: { code: CC.CHINA, name: "China" },
    [CC.CHRISTMAS_ISLAND]: { code: CC.CHRISTMAS_ISLAND, name: "Christmas Island" },
    [CC.COCOS_ISLANDS]: { code: CC.COCOS_ISLANDS, name: "Cocos (Keeling) Islands" },
    [CC.COLOMBIA]: { code: CC.COLOMBIA, name: "Colombia" },
    [CC.COMOROS]: { code: CC.COMOROS, name: "Comoros" },
    [CC.CONGO_BRAZZAVILLE]: { code: CC.CONGO_BRAZZAVILLE, name: "Congo" },
    [CC.CONGO_KINSHASA]: { code: CC.CONGO_KINSHASA, name: "Congo, the Democratic Republic of the" },
    [CC.COOK_ISLANDS]: { code: CC.COOK_ISLANDS, name: "Cook Islands" },
    [CC.COSTA_RICA]: { code: CC.COSTA_RICA, name: "Costa Rica" },
    [CC.COTE_D_IVOIRE]: { code: CC.COTE_D_IVOIRE, name: "Côte d'Ivoire" },
    [CC.CROATIA]: { code: CC.CROATIA, name: "Croatia" },
    [CC.CUBA]: { code: CC.CUBA, name: "Cuba" },
    [CC.CURACAO]: { code: CC.CURACAO, name: "Curaçao" },
    [CC.CYPRUS]: { code: CC.CYPRUS, name: "Cyprus" },
    [CC.CZECHIA]: { code: CC.CZECHIA, name: "Czech Republic" },
    [CC.DENMARK]: { code: CC.DENMARK, name: "Denmark" },
    [CC.DJIBOUTI]: { code: CC.DJIBOUTI, name: "Djibouti" },
    [CC.DOMINICA]: { code: CC.DOMINICA, name: "Dominica" },
    [CC.DOMINICAN_REPUBLIC]: { code: CC.DOMINICAN_REPUBLIC, name: "Dominican Republic" },
    [CC.ECUADOR]: { code: CC.ECUADOR, name: "Ecuador" },
    [CC.EGYPT]: { code: CC.EGYPT, name: "Egypt" },
    [CC.EL_SALVADOR]: { code: CC.EL_SALVADOR, name: "El Salvador" },
    [CC.EQUATORIAL_GUINEA]: { code: CC.EQUATORIAL_GUINEA, name: "Equatorial Guinea" },
    [CC.ERITREA]: { code: CC.ERITREA, name: "Eritrea" },
    [CC.ESTONIA]: { code: CC.ESTONIA, name: "Estonia" },
    [CC.ETHIOPIA]: { code: CC.ETHIOPIA, name: "Ethiopia" },
    [CC.FALKLAND_ISLANDS]: { code: CC.FALKLAND_ISLANDS, name: "Falkland Islands (Malvinas)" },
    [CC.FAROE_ISLANDS]: { code: CC.FAROE_ISLANDS, name: "Faroe Islands" },
    [CC.FIJI]: { code: CC.FIJI, name: "Fiji" },
    [CC.FINLAND]: { code: CC.FINLAND, name: "Finland" },
    [CC.FRANCE]: { code: CC.FRANCE, name: "France" },
    [CC.FRENCH_GUIANA]: { code: CC.FRENCH_GUIANA, name: "French Guiana" },
    [CC.FRENCH_POLYNESIA]: { code: CC.FRENCH_POLYNESIA, name: "French Polynesia" },
    [CC.FRENCH_SOUTHERN_TERRITORIES]: {
        code: CC.FRENCH_SOUTHERN_TERRITORIES,
        name: "French Southern Territories",
    },
    [CC.GABON]: { code: CC.GABON, name: "Gabon" },
    [CC.GAMBIA]: { code: CC.GAMBIA, name: "Gambia" },
    [CC.GEORGIA]: { code: CC.GEORGIA, name: "Georgia" },
    [CC.GERMANY]: { code: CC.GERMANY, name: "Germany" },
    [CC.GHANA]: { code: CC.GHANA, name: "Ghana" },
    [CC.GIBRALTAR]: { code: CC.GIBRALTAR, name: "Gibraltar" },
    [CC.GREECE]: { code: CC.GREECE, name: "Greece" },
    [CC.GREENLAND]: { code: CC.GREENLAND, name: "Greenland" },
    [CC.GRENADA]: { code: CC.GRENADA, name: "Grenada" },
    [CC.GUADELOUPE]: { code: CC.GUADELOUPE, name: "Guadeloupe" },
    [CC.GUAM]: { code: CC.GUAM, name: "Guam" },
    [CC.GUATEMALA]: { code: CC.GUATEMALA, name: "Guatemala" },
    [CC.GUERNSEY]: { code: CC.GUERNSEY, name: "Guernsey" },
    [CC.GUINEA]: { code: CC.GUINEA, name: "Guinea" },
    [CC.GUINEA_BISSAU]: { code: CC.GUINEA_BISSAU, name: "Guinea-Bissau" },
    [CC.GUYANA]: { code: CC.GUYANA, name: "Guyana" },
    [CC.HAITI]: { code: CC.HAITI, name: "Haiti" },
    [CC.HEARD_ISLAND_AND_MCDONALD_ISLANDS]: {
        code: CC.HEARD_ISLAND_AND_MCDONALD_ISLANDS,
        name: "Heard Island and McDonald Islands",
    },
    [CC.VATICAN]: { code: CC.VATICAN, name: "Holy See (Vatican City State)" },
    [CC.HONDURAS]: { code: CC.HONDURAS, name: "Honduras" },
    [CC.HONG_KONG]: { code: CC.HONG_KONG, name: "Hong Kong" },
    [CC.HUNGARY]: { code: CC.HUNGARY, name: "Hungary" },
    [CC.ICELAND]: { code: CC.ICELAND, name: "Iceland" },
    [CC.INDIA]: { code: CC.INDIA, name: "India" },
    [CC.INDONESIA]: { code: CC.INDONESIA, name: "Indonesia" },
    [CC.IRAN]: { code: CC.IRAN, name: "Iran, Islamic Republic of" },
    [CC.IRAQ]: { code: CC.IRAQ, name: "Iraq" },
    [CC.IRELAND]: { code: CC.IRELAND, name: "Ireland" },
    [CC.ISLE_OF_MAN]: { code: CC.ISLE_OF_MAN, name: "Isle of Man" },
    [CC.ISRAEL]: { code: CC.ISRAEL, name: "Israel" },
    [CC.ITALY]: { code: CC.ITALY, name: "Italy" },
    [CC.JAMAICA]: { code: CC.JAMAICA, name: "Jamaica" },
    [CC.JAPAN]: { code: CC.JAPAN, name: "Japan" },
    [CC.JERSEY]: { code: CC.JERSEY, name: "Jersey" },
    [CC.JORDAN]: { code: CC.JORDAN, name: "Jordan" },
    [CC.KAZAKHSTAN]: { code: CC.KAZAKHSTAN, name: "Kazakhstan" },
    [CC.KENYA]: { code: CC.KENYA, name: "Kenya" },
    [CC.KIRIBATI]: { code: CC.KIRIBATI, name: "Kiribati" },
    [CC.NORTH_KOREA]: { code: CC.NORTH_KOREA, name: "Korea, Democratic People's Republic of" },
    [CC.SOUTH_KOREA]: { code: CC.SOUTH_KOREA, name: "Korea, Republic of" },
    [CC.KUWAIT]: { code: CC.KUWAIT, name: "Kuwait" },
    [CC.KYRGYZSTAN]: { code: CC.KYRGYZSTAN, name: "Kyrgyzstan" },
    [CC.LAOS]: { code: CC.LAOS, name: "Lao People's Democratic Republic" },
    [CC.LATVIA]: { code: CC.LATVIA, name: "Latvia" },
    [CC.LEBANON]: { code: CC.LEBANON, name: "Lebanon" },
    [CC.LESOTHO]: { code: CC.LESOTHO, name: "Lesotho" },
    [CC.LIBERIA]: { code: CC.LIBERIA, name: "Liberia" },
    [CC.LIBYA]: { code: CC.LIBYA, name: "Libya" },
    [CC.LIECHTENSTEIN]: { code: CC.LIECHTENSTEIN, name: "Liechtenstein" },
    [CC.LITHUANIA]: { code: CC.LITHUANIA, name: "Lithuania" },
    [CC.LUXEMBOURG]: { code: CC.LUXEMBOURG, name: "Luxembourg" },
    [CC.MACAO]: { code: CC.MACAO, name: "Macao" },
    [CC.MACEDONIA]: { code: CC.MACEDONIA, name: "Macedonia, the former Yugoslav Republic of" },
    [CC.MADAGASCAR]: { code: CC.MADAGASCAR, name: "Madagascar" },
    [CC.MALAWI]: { code: CC.MALAWI, name: "Malawi" },
    [CC.MALAYSIA]: { code: CC.MALAYSIA, name: "Malaysia" },
    [CC.MALDIVES]: { code: CC.MALDIVES, name: "Maldives" },
    [CC.MALI]: { code: CC.MALI, name: "Mali" },
    [CC.MALTA]: { code: CC.MALTA, name: "Malta" },
    [CC.MARSHALL_ISLANDS]: { code: CC.MARSHALL_ISLANDS, name: "Marshall Islands" },
    [CC.MARTINIQUE]: { code: CC.MARTINIQUE, name: "Martinique" },
    [CC.MAURITANIA]: { code: CC.MAURITANIA, name: "Mauritania" },
    [CC.MAURITIUS]: { code: CC.MAURITIUS, name: "Mauritius" },
    [CC.MAYOTTE]: { code: CC.MAYOTTE, name: "Mayotte" },
    [CC.MEXICO]: { code: CC.MEXICO, name: "Mexico" },
    [CC.MICRONESIA]: { code: CC.MICRONESIA, name: "Micronesia, Federated States of" },
    [CC.MOLDOVA]: { code: CC.MOLDOVA, name: "Moldova, Republic of" },
    [CC.MONACO]: { code: CC.MONACO, name: "Monaco" },
    [CC.MONGOLIA]: { code: CC.MONGOLIA, name: "Mongolia" },
    [CC.MONTENEGRO]: { code: CC.MONTENEGRO, name: "Montenegro" },
    [CC.MONTSERRAT]: { code: CC.MONTSERRAT, name: "Montserrat" },
    [CC.MOROCCO]: { code: CC.MOROCCO, name: "Morocco" },
    [CC.MOZAMBIQUE]: { code: CC.MOZAMBIQUE, name: "Mozambique" },
    [CC.MYANMAR]: { code: CC.MYANMAR, name: "Myanmar" },
    [CC.NAMIBIA]: { code: CC.NAMIBIA, name: "Namibia" },
    [CC.NAURU]: { code: CC.NAURU, name: "Nauru" },
    [CC.NEPAL]: { code: CC.NEPAL, name: "Nepal" },
    [CC.NETHERLANDS]: { code: CC.NETHERLANDS, name: "Netherlands" },
    [CC.NEW_CALEDONIA]: { code: CC.NEW_CALEDONIA, name: "New Caledonia" },
    [CC.NEW_ZEALAND]: { code: CC.NEW_ZEALAND, name: "New Zealand" },
    [CC.NICARAGUA]: { code: CC.NICARAGUA, name: "Nicaragua" },
    [CC.NIGER]: { code: CC.NIGER, name: "Niger" },
    [CC.NIGERIA]: { code: CC.NIGERIA, name: "Nigeria" },
    [CC.NIUE]: { code: CC.NIUE, name: "Niue" },
    [CC.NORFOLK_ISLAND]: { code: CC.NORFOLK_ISLAND, name: "Norfolk Island" },
    [CC.NORTHERN_MARIANA_ISLANDS]: {
        code: CC.NORTHERN_MARIANA_ISLANDS,
        name: "Northern Mariana Islands",
    },
    [CC.NORWAY]: { code: CC.NORWAY, name: "Norway" },
    [CC.OMAN]: { code: CC.OMAN, name: "Oman" },
    [CC.PAKISTAN]: { code: CC.PAKISTAN, name: "Pakistan" },
    [CC.PALAU]: { code: CC.PALAU, name: "Palau" },
    [CC.PALESTINE]: { code: CC.PALESTINE, name: "Palestinian Territory, Occupied" },
    [CC.PANAMA]: { code: CC.PANAMA, name: "Panama" },
    [CC.PAPUA_NEW_GUINEA]: { code: CC.PAPUA_NEW_GUINEA, name: "Papua New Guinea" },
    [CC.PARAGUAY]: { code: CC.PARAGUAY, name: "Paraguay" },
    [CC.PERU]: { code: CC.PERU, name: "Peru" },
    [CC.PHILIPPINES]: { code: CC.PHILIPPINES, name: "Philippines" },
    [CC.PITCAIRN]: { code: CC.PITCAIRN, name: "Pitcairn" },
    [CC.POLAND]: { code: CC.POLAND, name: "Poland" },
    [CC.PORTUGAL]: { code: CC.PORTUGAL, name: "Portugal" },
    [CC.PUERTO_RICO]: { code: CC.PUERTO_RICO, name: "Puerto Rico" },
    [CC.QATAR]: { code: CC.QATAR, name: "Qatar" },
    [CC.RÉUNION]: { code: CC.RÉUNION, name: "Réunion" },
    [CC.ROMANIA]: { code: CC.ROMANIA, name: "Romania" },
    [CC.RUSSIA]: { code: CC.RUSSIA, name: "Russian Federation" },
    [CC.RWANDA]: { code: CC.RWANDA, name: "Rwanda" },
    [CC.SAINT_BARTHELEMY]: { code: CC.SAINT_BARTHELEMY, name: "Saint Barthélemy" },
    [CC.SAINT_HELENA]: {
        code: CC.SAINT_HELENA,
        name: "Saint Helena, Ascension and Tristan da Cunha",
    },
    [CC.SAINT_KITTS_AND_NEVIS]: { code: CC.SAINT_KITTS_AND_NEVIS, name: "Saint Kitts and Nevis" },
    [CC.SAINT_LUCIA]: { code: CC.SAINT_LUCIA, name: "Saint Lucia" },
    [CC.SAINT_MARTIN]: { code: CC.SAINT_MARTIN, name: "Saint Martin (French part)" },
    [CC.SAINT_PIERRE_AND_MIQUELON]: {
        code: CC.SAINT_PIERRE_AND_MIQUELON,
        name: "Saint Pierre and Miquelon",
    },
    [CC.SAINT_VINCENT_AND_THE_GRENADINES]: {
        code: CC.SAINT_VINCENT_AND_THE_GRENADINES,
        name: "Saint Vincent and the Grenadines",
    },
    [CC.SAMOA]: { code: CC.SAMOA, name: "Samoa" },
    [CC.SAN_MARINO]: { code: CC.SAN_MARINO, name: "San Marino" },
    [CC.SAO_TOME_AND_PRINCIPE]: { code: CC.SAO_TOME_AND_PRINCIPE, name: "Sao Tome and Principe" },
    [CC.SAUDI_ARABIA]: { code: CC.SAUDI_ARABIA, name: "Saudi Arabia" },
    [CC.SENEGAL]: { code: CC.SENEGAL, name: "Senegal" },
    [CC.SERBIA]: { code: CC.SERBIA, name: "Serbia" },
    [CC.SEYCHELLES]: { code: CC.SEYCHELLES, name: "Seychelles" },
    [CC.SIERRA_LEONE]: { code: CC.SIERRA_LEONE, name: "Sierra Leone" },
    [CC.SINGAPORE]: { code: CC.SINGAPORE, name: "Singapore" },
    [CC.SINT_MAARTEN]: { code: CC.SINT_MAARTEN, name: "Sint Maarten (Dutch part)" },
    [CC.SLOVAKIA]: { code: CC.SLOVAKIA, name: "Slovakia" },
    [CC.SLOVENIA]: { code: CC.SLOVENIA, name: "Slovenia" },
    [CC.SOLOMON_ISLANDS]: { code: CC.SOLOMON_ISLANDS, name: "Solomon Islands" },
    [CC.SOMALIA]: { code: CC.SOMALIA, name: "Somalia" },
    [CC.SOUTH_AFRICA]: { code: CC.SOUTH_AFRICA, name: "South Africa" },
    [CC.SOUTH_GEORGIA_AND_THE_SOUTH_SANDWICH_ISLANDS]: {
        code: CC.SOUTH_GEORGIA_AND_THE_SOUTH_SANDWICH_ISLANDS,
        name: "South Georgia and the South Sandwich Islands",
    },
    [CC.SOUTH_SUDAN]: { code: CC.SOUTH_SUDAN, name: "South Sudan" },
    [CC.SPAIN]: { code: CC.SPAIN, name: "Spain" },
    [CC.SRI_LANKA]: { code: CC.SRI_LANKA, name: "Sri Lanka" },
    [CC.SUDAN]: { code: CC.SUDAN, name: "Sudan" },
    [CC.SURINAME]: { code: CC.SURINAME, name: "Suriname" },
    [CC.SVALBARD_AND_JAN_MAYEN]: {
        code: CC.SVALBARD_AND_JAN_MAYEN,
        name: "Svalbard and Jan Mayen",
    },
    [CC.SWAZILAND]: { code: CC.SWAZILAND, name: "Swaziland" },
    [CC.SWEDEN]: { code: CC.SWEDEN, name: "Sweden" },
    [CC.SWITZERLAND]: { code: CC.SWITZERLAND, name: "Switzerland" },
    [CC.SYRIA]: { code: CC.SYRIA, name: "Syrian Arab Republic" },
    [CC.TAIWAN]: { code: CC.TAIWAN, name: "Taiwan, Province of China" },
    [CC.TAJIKISTAN]: { code: CC.TAJIKISTAN, name: "Tajikistan" },
    [CC.TANZANIA]: { code: CC.TANZANIA, name: "Tanzania, United Republic of" },
    [CC.THAILAND]: { code: CC.THAILAND, name: "Thailand" },
    [CC.TIMOR_LESTE]: { code: CC.TIMOR_LESTE, name: "Timor-Leste" },
    [CC.TOGO]: { code: CC.TOGO, name: "Togo" },
    [CC.TOKELAU]: { code: CC.TOKELAU, name: "Tokelau" },
    [CC.TONGA]: { code: CC.TONGA, name: "Tonga" },
    [CC.TRINIDAD_AND_TOBAGO]: { code: CC.TRINIDAD_AND_TOBAGO, name: "Trinidad and Tobago" },
    [CC.TUNISIA]: { code: CC.TUNISIA, name: "Tunisia" },
    [CC.TURKEY]: { code: CC.TURKEY, name: "Turkey" },
    [CC.TURKMENISTAN]: { code: CC.TURKMENISTAN, name: "Turkmenistan" },
    [CC.TURKS_AND_CAICOS_ISLANDS]: {
        code: CC.TURKS_AND_CAICOS_ISLANDS,
        name: "Turks and Caicos Islands",
    },
    [CC.TUVALU]: { code: CC.TUVALU, name: "Tuvalu" },
    [CC.UGANDA]: { code: CC.UGANDA, name: "Uganda" },
    [CC.UKRAINE]: { code: CC.UKRAINE, name: "Ukraine" },
    [CC.UNITED_ARAB_EMIRATES]: { code: CC.UNITED_ARAB_EMIRATES, name: "United Arab Emirates" },
    [CC.UNITED_KINGDOM]: { code: CC.UNITED_KINGDOM, name: "United Kingdom" },
    [CC.UNITED_STATES]: { code: CC.UNITED_STATES, name: "United States" },
    [CC.UNITED_STATES_MINOR_OUTLYING_ISLANDS]: {
        code: CC.UNITED_STATES_MINOR_OUTLYING_ISLANDS,
        name: "United States Minor Outlying Islands",
    },
    [CC.URUGUAY]: { code: CC.URUGUAY, name: "Uruguay" },
    [CC.UZBEKISTAN]: { code: CC.UZBEKISTAN, name: "Uzbekistan" },
    [CC.VANUATU]: { code: CC.VANUATU, name: "Vanuatu" },
    [CC.VENEZUELA]: { code: CC.VENEZUELA, name: "Venezuela, Bolivarian Republic of" },
    [CC.VIETNAM]: { code: CC.VIETNAM, name: "Viet Nam" },
    [CC.BRITISH_VIRGIN_ISLANDS]: {
        code: CC.BRITISH_VIRGIN_ISLANDS,
        name: "Virgin Islands, British",
    },
    [CC.VIRGIN_ISLANDS]: { code: CC.VIRGIN_ISLANDS, name: "Virgin Islands, U.S." },
    [CC.WALLIS_AND_FUTUNA]: { code: CC.WALLIS_AND_FUTUNA, name: "Wallis and Futuna" },
    [CC.WESTERN_SAHARA]: { code: CC.WESTERN_SAHARA, name: "Western Sahara" },
    [CC.YEMEN]: { code: CC.YEMEN, name: "Yemen" },
    [CC.ZAMBIA]: { code: CC.ZAMBIA, name: "Zambia" },
    [CC.ZIMBABWE]: { code: CC.ZIMBABWE, name: "Zimbabwe" },
} as const
