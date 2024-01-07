import logging
import bdkpython as bdk

logger = logging.getLogger(__name__)


# Character sets used in the functions
INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Generators for the polymod function
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


def descsum_polymod(symbols):
    """Internal function that computes the descriptor checksum."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def descsum_expand(s):
    """Internal function that does the character to symbol expansion"""
    groups = []
    symbols = []
    for c in s:
        if not c in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descsum_check(s):
    """Verify that the checksum is correct in a descriptor"""
    if s[-9] != "#" or not all(x in CHECKSUM_CHARSET for x in s[-8:]):
        return False
    symbols = descsum_expand(s[:-9]) + [CHECKSUM_CHARSET.find(x) for x in s[-8:]]
    return descsum_polymod(symbols) == 1


def get_checksum_of_descriptor(s):
    """Add a checksum to a descriptor without"""
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return "".join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def is_valid_descriptor_checksum(full_descriptor):
    """Check if the checksum of a Bitcoin output descriptor is correct."""
    parts = full_descriptor.split("#")
    if len(parts) != 2:
        raise ValueError("Invalid descriptor format")
    descriptor, provided_checksum = parts
    computed_checksum = get_checksum_of_descriptor(descriptor)
    return computed_checksum == provided_checksum


def has_checksum(descriptor):
    """Check if the Bitcoin output descriptor has a checksum."""
    parts = descriptor.split("#")
    return len(parts) == 2 and len(parts[1]) == 8


def add_checksum_to_descriptor(descriptor_str):
    """Add the correct checksum to a Bitcoin output descriptor."""
    if has_checksum(descriptor_str):
        if is_valid_descriptor_checksum(descriptor_str):
            return descriptor_str
        else:
            raise ValueError("Invalid Checksum already in descriptor")

    checksum = get_checksum_of_descriptor(descriptor_str)
    return f"{descriptor_str}#{checksum}"


def strip_checksum(descriptor_str: str):
    parts = descriptor_str.split("#")
    assert len(parts) == 2 and len(parts[1]) == 8
    return parts[0]


def replace_in_descriptor(descriptor_str, search_str, replace_str):
    assert is_valid_descriptor_checksum(descriptor_str), "Checksum is not valid"
    return add_checksum_to_descriptor(strip_checksum(descriptor_str).replace(search_str, replace_str))


def split_wallet_descriptor(multipath_descriptor_str: str):
    logger.warning(
        "This function is unsafe and must be replaced by bdk/rust miniscript. See https://github.com/bitcoindevkit/bdk/issues/1021"
    )
    assert is_valid_descriptor_checksum(multipath_descriptor_str)

    assert "/<0;1>/*" in multipath_descriptor_str

    return [
        replace_in_descriptor(multipath_descriptor_str, "/<0;1>/*", replace_str)
        for replace_str in ["/0/*", "/1/*"]
    ]


class MultipathDescriptor:
    """
    Will create main+change BDK single and multisig descriptors, no matter if '/<0;1>/*' or '/0/*' or '/1/*' is specified

    This is a temporary class, that can be removed once https://github.com/bitcoindevkit/bdk/issues/1021  is done.
    """

    def __init__(self, bdk_descriptor: bdk.Descriptor, change_descriptor: bdk.Descriptor) -> None:
        self.bdk_descriptors = [bdk_descriptor, change_descriptor]

    @classmethod
    def from_descriptor_str(cls, descriptor_str: str, network: bdk.Network) -> "MultipathDescriptor":
        def count_closing_brackets(s):
            count = 0
            for char in reversed(s):
                if char == ")":
                    count += 1
                else:
                    break
            return count

        descriptor_str = add_checksum_to_descriptor(descriptor_str)

        # check if the descriptor_str is a combined one:
        if "/<0;1>/*" in descriptor_str:
            receive_descriptor_str, change_descriptor_str = split_wallet_descriptor(descriptor_str)
        elif "/0/*" in descriptor_str or "/1/*" in descriptor_str:
            receive_descriptor_str = replace_in_descriptor(descriptor_str, "/1/*", "/0/*")
            change_descriptor_str = replace_in_descriptor(descriptor_str, "/0/*", "/1/*")
        else:
            # sparrow qr code misses the change derivation path completely

            # check if checksum
            stripped = strip_checksum(descriptor_str)

            count_brackets = count_closing_brackets(stripped)
            receive_descriptor_str = stripped[:-count_brackets] + "/0/*" + stripped[-count_brackets:]
            change_descriptor_str = stripped[:-count_brackets] + "/1/*" + stripped[-count_brackets:]

        return MultipathDescriptor(
            bdk.Descriptor(receive_descriptor_str, network=network),
            bdk.Descriptor(change_descriptor_str, network=network),
        )

    def as_string(self) -> str:
        return self._as_string(only_public=True)

    def as_string_private(self) -> str:
        return self._as_string(only_public=False)

    def _as_string(self, only_public=False) -> str:
        logger.warning(
            "This function is unsafe and must be replaced by bdk/rust miniscript. See https://github.com/bitcoindevkit/bdk/issues/1021"
        )
        assert len(self.bdk_descriptors) == 2

        descriptors = [d.as_string() if only_public else d.as_string_private() for d in self.bdk_descriptors]
        # check that these are really just the paths "/0/*" and "/1/*"
        assert all([strip_checksum(d).count(f"/{i}/*)") == 1 for i, d in enumerate(descriptors)])

        # only take the 1 descriptor, and put the /<0;1>/ in there
        return replace_in_descriptor(descriptors[0], f"/{0}/*", f"/<0;1>/*")
