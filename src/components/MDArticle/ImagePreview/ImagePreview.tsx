import { CloseButton, Image, Overlay } from "@mantine/core"
import { FC } from "react"
import { useClickOutside, useHotkeys } from "@mantine/hooks"
import { RemoveScroll } from "@mantine/core"

interface Props {
    src: string | null
    onClose: () => void
}

const ImagePreview: FC<Props> = ({ src, onClose }) => {
    const ref = useClickOutside(onClose)
    useHotkeys([["escape", onClose]])

    return (
        <>
            {src && (
                <RemoveScroll>
                    <Overlay w="100vw" h="100vh" pos="fixed" blur={3}>
                        <CloseButton
                            onClick={onClose}
                            size="lg"
                            pos="absolute"
                            style={{ right: 10, top: 10 }}
                        />
                        <Image
                            pos="absolute"
                            style={{ top: "50%", left: "50%", transform: "translate(-50%, -50%)" }}
                            src={src}
                            ref={ref}
                            mah="85vh"
                            maw="95vw"
                            w="auto"
                            fit="contain"
                        />
                    </Overlay>
                </RemoveScroll>
            )}
        </>
    )
}

export default ImagePreview
