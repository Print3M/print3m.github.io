import { CountryCode } from "./countries"
import { maps } from "./maps"

export type MapKey = keyof typeof maps

export interface Country {
    code: CountryCode
    name: string
}

export interface DataSet {
    label: string
    color: string
    members: CountryCode[]
}

export interface MapView {
    label: string
    fullName: string
    description?: string
    dataSets: DataSet[]
}
