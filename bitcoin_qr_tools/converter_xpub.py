import hashlib
import logging

import base58
import bdkpython as bdk

from bitcoin_qr_tools.utils import WrongNetwork

logger = logging.getLogger(__name__)


class ConverterXpub:
    # Mapping of SLIP-132 version bytes to BIP32 version bytes
    version_bytes_map = {
        bytes.fromhex("04b24746"): bytes.fromhex("0488b21e"),  # zpub to xpub
        bytes.fromhex("04b2430c"): bytes.fromhex("0488ade4"),  # zprv to xprv
        bytes.fromhex("049d7cb2"): bytes.fromhex("0488b21e"),  # ypub to xpub
        bytes.fromhex("049d7878"): bytes.fromhex("0488ade4"),  # yprv to xprv
        bytes.fromhex("0295b43f"): bytes.fromhex("0488b21e"),  # Ypub to xpub
        bytes.fromhex("0295b005"): bytes.fromhex("0488ade4"),  # Yprv to xprv
        bytes.fromhex("02aa7ed3"): bytes.fromhex("0488b21e"),  # Zpub to xpub
        bytes.fromhex("02aa7a99"): bytes.fromhex("0488ade4"),  # Zprv to xprv
        bytes.fromhex("045f1cf6"): bytes.fromhex("043587cf"),  # vpub to tpub
        bytes.fromhex("045f18bc"): bytes.fromhex("04358394"),  # vprv to tprv
        bytes.fromhex("044a5262"): bytes.fromhex("043587cf"),  # upub to tpub
        bytes.fromhex("044a4e28"): bytes.fromhex("04358394"),  # uprv to tprv
        bytes.fromhex("024289ef"): bytes.fromhex("043587cf"),  # Upub to tpub
        bytes.fromhex("024285b5"): bytes.fromhex("04358394"),  # Uprv to tprv
        bytes.fromhex("02575483"): bytes.fromhex("043587cf"),  # Vpub to tpub
        bytes.fromhex("02575048"): bytes.fromhex("04358394"),  # Vprv to tprv
    }

    @classmethod
    def xpub_matches_network(cls, xpub: str, network: bdk.Network) -> bool:
        if network == bdk.Network.BITCOIN:
            if not xpub.startswith("xpub"):
                return False
        else:
            if not xpub.startswith("tpub"):
                return False
        return True

    @classmethod
    def ensure_xpub_matches_network(cls, xpub: str, network: bdk.Network):
        "Raises an exception if not matching"
        if network == bdk.Network.BITCOIN:
            if not xpub.startswith("xpub"):
                raise WrongNetwork(f"{xpub} doesnt start with xpub, which is required for {network}")
        else:
            if not xpub.startswith("tpub"):
                raise WrongNetwork(f"{xpub} doesnt start with tpub, which is required for {network}")

    @classmethod
    def is_xpub(cls, s: str) -> bool:
        if not s.isalnum():
            return False
        first_four_letters = s[:4]
        return first_four_letters.endswith("pub")

    ################ here is the slip132 part
    ### see https://github.com/satoshilabs/slips/blob/master/slip-0132.md

    @classmethod
    def get_slip132_version_bytes(cls, slip132_key: str) -> bytes:
        """Get the version bytes from a SLIP-132 key."""
        raw_extended_key = base58.b58decode(slip132_key)
        return raw_extended_key[:4]

    @classmethod
    def base58check_decode(cls, s: str) -> bytes:
        """Decode a Base58Check encoded string to bytes"""
        # Decode the string
        data = base58.b58decode(s)

        # Split the data into the payload and the checksum
        check_sum = data[-4:]
        payload = data[:-4]

        # Calculate the checksum of the payload
        calculated_check_sum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

        # Compare the calculated checksum with the checksum from the data
        if check_sum != calculated_check_sum:
            raise ValueError("Invalid checksum")

        return payload

    @classmethod
    def normalized_to_bip32(cls, xpub: str) -> str:
        if ConverterXpub.is_slip132(xpub):
            converted = cls.convert_slip132_to_bip32(xpub)
            logger.debug(f"Converting SLIP132 to Bip32: {xpub} -> {converted}")
            return converted
        return xpub

    @classmethod
    def convert_slip132_to_bip32(cls, slip132_key: str) -> str:
        """Convert a SLIP-132 extended key to a BIP32 extended key."""
        raw_extended_key = cls.base58check_decode(slip132_key)
        slip132_version_bytes = raw_extended_key[:4]

        # Lookup the corresponding BIP32 version bytes
        bip32_version_bytes = cls.version_bytes_map.get(slip132_version_bytes)
        if bip32_version_bytes is None:
            raise ValueError("Unsupported SLIP-132 version bytes")

        # Replace the version bytes of the raw key
        replaced_version_key = bip32_version_bytes + raw_extended_key[4:]

        # Calculate the checksum of the replaced version key
        check_sum = hashlib.sha256(hashlib.sha256(replaced_version_key).digest()).digest()[:4]

        # Encode the replaced version key + checksum into Base58
        bip32_key = base58.b58encode(replaced_version_key + check_sum).decode()

        return bip32_key

    @classmethod
    def is_slip132(cls, key: str) -> bool:
        try:
            return cls.get_slip132_version_bytes(key) in cls.version_bytes_map
        except:
            return False
