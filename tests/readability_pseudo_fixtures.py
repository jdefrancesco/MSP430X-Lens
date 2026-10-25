def encode_words(*words: int) -> bytes:
    return b"".join(word.to_bytes(2, "little") for word in words)


def signed_index_words(src: int, dst: int, bias: int = 0x24) -> tuple[int, ...]:
    return (
        (src << 8) | 0xC0 | dst,
        0x0650 | dst,
        0x0250 | src,
        0x5000 | (src << 8) | dst,
        0x5030 | dst,
        bias,
        0x0E40 | dst,
        0x0D40 | dst,
    )


def wordpair_load_words(base: int, low: int, dst: int) -> tuple[int, ...]:
    return (
        0x4030 | (base << 8) | low,
        0x4030 | (base << 8) | dst,
        0x180F,
        0x5040 | (dst << 8) | dst,
        0x1800,
        0xD040 | (low << 8) | dst,
    )


def msb_mask_words(src: int, scratch: int, dst: int) -> tuple[int, ...]:
    return (
        0x00C0 | (src << 8) | scratch,
        0xB030 | scratch,
        0x8000,
        0x7000 | (dst << 8) | dst,
        0xE330 | dst,
    )


def aligned_advance_words(offset: int, base: int, dst: int) -> tuple[int, ...]:
    return (
        0x0E40 | offset,
        0x0D40 | offset,
        (offset << 8) | 0x00E0 | base,
        0x00C0 | (base << 8) | dst,
        0x00A0 | dst,
        0x0001,
        0x1F80,
        0xF070 | dst,
        0xFFFE,
    )


UNSIGNED_INDEX_WORDS = (
    0x430C,
    0x0FCD,
    0x0CCE,
    0x025D,
    0x6E0E,
    0x025F,
    0x6C0C,
    0x025F,
    0x6C0C,
    0x5D0F,
    0x6E0C,
    0x180F,
    0x5C4C,
    0x1800,
    0xDF4C,
    0x00AC,
    0x7000,
)
