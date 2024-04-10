import { slugify } from "@/utils/utils"
import { Text, Title, TitleOrder } from "@mantine/core"
import { IconLink } from "@tabler/icons-react"
import Link from "next/link"
import { FC } from "react"
import classes from "./Heading.module.css"

interface Props {
    text: string
    order: TitleOrder
}

const Heading: FC<Props> = ({ order, text }) => {
    const anchor = slugify(text)

    return (
        <Title order={order} className={classes.heading} ta="left">
            <Link href={`#${anchor}`} className={classes.anchor}>
                <Text display="inline" ml={6}>
                    <IconLink size={18} />
                </Text>
            </Link>
            {text}
        </Title>
    )
}

export default Heading
