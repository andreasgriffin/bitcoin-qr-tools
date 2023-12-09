import re, urllib
from typing import List, Callable, Union, Optional, Tuple, Dict
from decimal import Decimal
import bdkpython as bdk
import base64, json
from urtypes.crypto import PSBT as UR_PSBT
from urtypes.crypto import Output as US_OUTPUT
from ur.ur_decoder import URDecoder
from urtypes.bytes import Bytes as UR_BYTES
import hashlib
import base58
import logging
import enum
from .multipath_descriptor import MultipathDescriptor

BITCOIN_BIP21_URI_SCHEME = "bitcoin"
logger = logging.getLogger(__name__)


def is_bitcoin_address(s):
    if re.search(r"^bitcoin\:.*", s, re.IGNORECASE):
        return True
    elif re.search(r"^((bc1|tb1|bcr|[123]|[mn])[a-zA-HJ-NP-Z0-9]{25,62})$", s):
        # TODO: Handle regtest bcrt?
        return True
    else:
        return False


class InvalidBitcoinURI(Exception):
    pass


def serialized_to_hex(serialized):
    return bytes(serialized).hex()


def decode_bip21_uri(uri: str) -> dict:
    """Raises InvalidBitcoinURI on malformed URI."""
    TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 21000000
    COIN = 100000000

    if not isinstance(uri, str):
        raise InvalidBitcoinURI(f"expected string, not {repr(uri)}")

    if ":" not in uri:
        if not is_bitcoin_address(uri):
            raise InvalidBitcoinURI("Not a bitcoin address")
        return {"address": uri}

    u = urllib.parse.urlparse(uri)
    if u.scheme.lower() != BITCOIN_BIP21_URI_SCHEME:
        raise InvalidBitcoinURI("Not a bitcoin URI")
    address = u.path

    # python for android fails to parse query
    if address.find("?") > 0:
        address, query = u.path.split("?")
        pq = urllib.parse.parse_qs(query)
    else:
        pq = urllib.parse.parse_qs(u.query)

    for k, v in pq.items():
        if len(v) != 1:
            raise InvalidBitcoinURI(f"Duplicate Key: {repr(k)}")

    out = {k: v[0] for k, v in pq.items()}
    if address:
        if not is_bitcoin_address(address):
            raise InvalidBitcoinURI(f"Invalid bitcoin address: {address}")
        out["address"] = address
    if "amount" in out:
        am = out["amount"]
        try:
            m = re.match(r"([0-9.]+)X([0-9])", am)
            if m:
                k = int(m.group(2)) - 8
                amount = Decimal(m.group(1)) * pow(Decimal(10), k)
            else:
                amount = Decimal(am) * COIN
            if amount > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
                raise InvalidBitcoinURI(f"amount is out-of-bounds: {amount!r} BTC")
            out["amount"] = int(amount)
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'amount' field: {repr(e)}") from e
    if "message" in out:
        out["message"] = out["message"]
        out["memo"] = out["message"]
    if "time" in out:
        try:
            out["time"] = int(out["time"])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'time' field: {repr(e)}") from e
    if "exp" in out:
        try:
            out["exp"] = int(out["exp"])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'exp' field: {repr(e)}") from e
    if "sig" in out:
        try:
            out["sig"] = serialized_to_hex(out["sig"])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'sig' field: {repr(e)}") from e
    if "lightning" in out:
        raise InvalidBitcoinURI(f"Failed to decode 'lightning' field: {e!r}") from e

    return out


def is_xpub(s):
    if not s.isalnum():
        return False
    first_four_letters = s[:4]
    return first_four_letters.endswith("pub")


def extract_keystore(s):
    """
    Splits 1 keystore,e.g. "[a42c6dd3/84'/1'/0']xpub/0/*"
    into fingerprint, derivation_path, xpub, wallet_path

    It also replaces the "'" into "h"

    It overwrites fingerprint, derivation_path, xpub  in default_keystore.
    """

    def extract_groups(string, pattern):
        match = re.match(pattern, string)
        if match is None:
            raise Exception(f"'{string}' does not match the required pattern!")
        return match.groups()

    groups = extract_groups(s, r"\[(.*?)\/(.*?)\](.*?)(\/.*?)?$")

    return {
        "fingerprint": groups[0],
        "derivation_path": "m/" + groups[1].replace("h", "'"),
        "xpub": groups[2],
        "further_derivation_path": groups[3],
    }


def is_valid_bitcoin_hash(hash):
    import re

    if re.match("^[a-f0-9]{64}$", hash):
        return True
    else:
        return False


def is_valid_wallet_fingerprint(fingerprint):
    import re

    if re.match("^[a-fA-F0-9]{8}$", fingerprint):
        return True
    else:
        return False


###############  here is the simplified electrum base43 code
def base43_decode(v: str):
    __b43chars = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"
    assert len(__b43chars) == 43
    __b43chars_inv = {v: k for k, v in enumerate(__b43chars)}

    base = 43
    num = 0

    # Remove leading zeros and adjust length
    v = v.lstrip("0")

    # Convert each character to a number using the inverse character map
    for char in v:
        num = num * base + __b43chars_inv[ord(char)]

    # Convert the number to bytes
    return num.to_bytes((num.bit_length() + 7) // 8, "big")


################ here is the slip132 part
### see https://github.com/satoshilabs/slips/blob/master/slip-0132.md


def get_version_bytes(slip132_key):
    """Get the version bytes from a SLIP-132 key."""
    raw_extended_key = base58.b58decode(slip132_key)
    return raw_extended_key[:4]


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


def base58check_decode(s):
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


def convert_slip132_to_bip32(slip132_key):
    """Convert a SLIP-132 extended key to a BIP32 extended key."""
    raw_extended_key = base58check_decode(slip132_key)
    slip132_version_bytes = raw_extended_key[:4]

    # Lookup the corresponding BIP32 version bytes
    bip32_version_bytes = version_bytes_map.get(slip132_version_bytes)
    if bip32_version_bytes is None:
        raise ValueError("Unsupported SLIP-132 version bytes")

    # Replace the version bytes of the raw key
    replaced_version_key = bip32_version_bytes + raw_extended_key[4:]

    # Calculate the checksum of the replaced version key
    check_sum = hashlib.sha256(hashlib.sha256(replaced_version_key).digest()).digest()[
        :4
    ]

    # Encode the replaced version key + checksum into Base58
    bip32_key = base58.b58encode(replaced_version_key + check_sum).decode()

    return bip32_key


def is_slip132(key):
    return get_version_bytes(key) in version_bytes_map


class DataType(enum.Enum):
    Bip21 = enum.auto()  # https://bips.dev/21/
    Descriptor = enum.auto()
    MultiPathDescriptor = enum.auto()
    Xpub = enum.auto()
    Fingerprint = enum.auto()
    KeyStoreInfo = enum.auto()  # FingerPrint, Derivation path, Xpub
    PSBT = enum.auto()
    Txid = enum.auto()
    Tx = enum.auto()


class Data:
    """
    Recognized bitcoin data in a string, gives the data and the DataType
    """

    def __init__(self, data, data_type: DataType) -> None:
        self.data = data
        self.data_type = data_type

    def data_as_string(self):
        if isinstance(self.data, str):
            return self.data
        if self.data_type == DataType.Bip21:
            return str(self.data)
        if self.data_type == DataType.Descriptor:
            return self.data.as_string_private() if self.data else self.data
        if self.data_type == DataType.MultiPathDescriptor:
            return self.data.as_string_private() if self.data else self.data
        if self.data_type == DataType.KeyStoreInfo:
            return str(self.data)
        if self.data_type == DataType.PSBT:
            return str(self.data.serialize())
        if self.data_type == DataType.Tx:
            return str(serialized_to_hex(self.data.serialize()))

        return str(self.data)

    def __str__(self) -> str:
        return f"{self.data_type.name}: {self.data_as_string()}"

    @classmethod
    def _try_decode_bip21(cls, s):
        try:
            return decode_bip21_uri(s)
        except Exception:
            pass

    @classmethod
    def _try_get_descriptor(cls, s, network):
        try:
            descriptor = bdk.Descriptor(s, network)
            if descriptor:
                logger.debug("detected descriptor")
                return descriptor
        except Exception:
            pass

        try:
            specter_dict = json.loads(s)
            if "descriptor" in specter_dict:
                descriptor = bdk.Descriptor(specter_dict["descriptor"], network)
                logger.debug("detected descriptor")
                return descriptor
        except Exception:
            pass

    @classmethod
    def _try_get_multipath_descriptor(cls, s, network):
        try:
            multipath_descriptor = MultipathDescriptor.from_descriptor_str(s, network)
            if multipath_descriptor:
                logger.debug("detected descriptor")
                return multipath_descriptor
        except Exception:
            pass

    @classmethod
    def _decoding_strategies(cls):
        return [
            lambda x: base64.b64decode(x),  # base64 decoding
            lambda x: bytes.fromhex(x),  # hex decoding
            lambda x: base43_decode(x),  # base43 decoding
            lambda x: base58.b58decode(x),
        ]

    @classmethod
    def _try_decode_psbt(cls, s):
        psbt_magic_bytes = b"psbt\xff"

        # Try each decoding strategy in the loop
        for decode in cls._decoding_strategies():
            try:
                decoded = decode(s)
                if decoded[:5] == psbt_magic_bytes:
                    return bdk.PartiallySignedTransaction(
                        base64.b64encode(decoded).decode()
                    )
            except Exception:
                continue  # If one strategy fails, try the next

        return None

    @classmethod
    def _try_decode_serialized_transaction(cls, s):
        # Try each decoding strategy in the loop
        for decode in cls._decoding_strategies():
            try:
                decoded = decode(s)
                return bdk.Transaction(decoded)
            except Exception:
                continue  # If one strategy fails, try the next

        return None

    @classmethod
    def _try_extract_keystore(cls, s, network):
        keystore_info = None
        try:
            keystore_info = extract_keystore(s)
        except:
            pass

        if keystore_info:
            logger.debug("detected keystore_info")
            if is_slip132(keystore_info.get("xpub")):
                keystore_info["xpub"] = convert_slip132_to_bip32(
                    keystore_info.get("xpub")
                )
            return keystore_info

        try:
            cobo_dict = json.loads(s)
            keystore_info = {}
            key_map = {"fingerprint": "xfp", "derivation_path": "path", "xpub": "xpub"}
            for key, cobo_key in key_map.items():
                if cobo_key in cobo_dict:
                    keystore_info[key] = cobo_dict[cobo_key]
                if key in cobo_dict:
                    keystore_info[key] = cobo_dict[key]
            if keystore_info:
                return keystore_info
        except Exception:
            pass

        return None

    @classmethod
    def from_str(cls, s, network):
        s = s.strip()
        data = None

        # Sequence of checks to identify the type of data in `s`
        if decoded_bip21 := cls._try_decode_bip21(s):
            return Data(decoded_bip21, DataType.Bip21)

        if is_xpub(s):
            data = convert_slip132_to_bip32(s) if is_slip132(s) else s
            return Data(data, DataType.Xpub)

        if descriptor := cls._try_get_descriptor(s, network):
            return Data(descriptor, DataType.Descriptor)

        if descriptor := cls._try_get_multipath_descriptor(s, network):
            return Data(descriptor, DataType.MultiPathDescriptor)

        if is_valid_bitcoin_hash(s):
            return Data(s, DataType.Txid)

        if is_valid_wallet_fingerprint(s):
            return Data(s, DataType.Fingerprint)

        if psbt := cls._try_decode_psbt(s):
            return Data(psbt, DataType.PSBT)

        if tx := cls._try_decode_serialized_transaction(s):
            return Data(tx, DataType.Tx)

        if keystore_info := cls._try_extract_keystore(s, network):
            return Data(keystore_info, DataType.KeyStoreInfo)

        raise Exception(f"{s} Could not be decoded")


class BaseCollector:
    def __init__(self, network) -> None:
        self.data: Data = None
        self.network = network

    def is_correct_data_format(self, s):
        pass

    def is_complete(self) -> bool:
        pass

    def get_complete_data(self) -> Data:
        pass

    def add(self, s: str):
        pass

    def clear(self):
        self.data = None

    def estimated_percent_complete(self):
        pass


class SinglePassCollector(BaseCollector):
    def is_correct_data_format(self, s):
        return True

    def is_complete(self) -> bool:
        return bool(self.data)

    def get_complete_data(self) -> Data:
        return self.data

    def add(self, s: str):
        self.data = Data.from_str(s, network=self.network)
        return self.data

    def estimated_percent_complete(self):
        return float(bool(self.data))


class SpecterDIYCollector(BaseCollector):
    def __init__(self, network) -> None:
        super().__init__(network)
        self.clear()

    def is_correct_data_format(self, s):
        return self.extract_specter_diy_qr_part(s) is not None

    def is_complete(self) -> bool:
        return len(self.parts) == self.total_parts

    def get_complete_data(self) -> Data:
        if not self.is_complete():
            return None

        total_s = ""
        for i in range(1, self.total_parts + 1):
            total_s += self.parts[i]
        return Data.from_str(total_s, network=self.network)

    def extract_specter_diy_qr_part(self, s) -> Tuple[int, int, str]:
        "pMofM something  ->  (M,N,something)"
        pattern = r"^p(\d+)of(\d+)\s(.*)"
        match = re.match(pattern, s)
        if match:
            return int(match.group(1)), int(match.group(2)), match.group(3)
        else:
            return None

    def add(self, s: str):
        m, n, data = self.extract_specter_diy_qr_part(s)
        if (self.total_parts is not None) and n != self.total_parts:
            # if n != self.total_parts then, it appears we switched to a different qrcode
            self.clear()

        if self.total_parts is None:
            self.total_parts = n

        self.parts[m] = data
        return data

    def clear(self):
        super().clear()
        self.parts: Dict[int, str] = {}
        self.total_parts = None

    def estimated_percent_complete(self):
        if not self.total_parts:
            return 0
        return min(len(self.parts) / max(self.total_parts, 1), 1)


class URCollector(BaseCollector):
    def __init__(self, network) -> None:
        super().__init__(network)
        self.clear()

    def is_psbt(self, s: str):
        return re.search("^UR:CRYPTO-PSBT/", s, re.IGNORECASE)

    def is_descriptor(self, s: str):
        return re.search("^UR:CRYPTO-OUTPUT/", s, re.IGNORECASE)

    def is_descriptor(self, s: str):
        return re.search("^UR:CRYPTO-OUTPUT/", s, re.IGNORECASE)

    def is_bytes(self, s: str):
        return re.search("^UR:BYTES/", s, re.IGNORECASE)

    def is_correct_data_format(self, s):
        if self.is_psbt(s):
            return True
        if self.is_descriptor(s):
            return True
        if self.is_bytes(s):
            return True

        return False

    def is_complete(self) -> bool:
        return self.decoder.is_complete()

    def get_complete_data(self) -> Data:
        if self.decoder.result.type == "crypto-psbt":
            qr_content = UR_PSBT.from_cbor(self.decoder.result.cbor).data
            s = base64.b64encode(qr_content).decode("utf-8")
        if self.decoder.result.type == "crypto-output":
            s = US_OUTPUT.from_cbor(self.decoder.result.cbor).descriptor()
        if self.decoder.result.type == "bytes":
            raw = UR_BYTES.from_cbor(self.decoder.result.cbor).data
            s = raw.hex()

        return Data.from_str(s, network=self.network)

    def add(self, s: str):
        self.decoder.receive_part(s)
        logger.debug(
            f"{round(self.decoder.estimated_percent_complete()*100)}% complete"
        )

        # if the decoder is stuck for some reason. reset it
        # this part must be done AFTER receive_part(s)
        if self.received_parts > self.decoder.expected_part_count() * 2:
            logger.debug(
                f"{self.received_parts}/{self.decoder.expected_part_count()} parts received, but incomplete. Resetting"
            )
            self.clear()

        if self.last_received_part != s:
            self.received_parts += 1
            self.last_received_part = s
        return s

    def clear(self):
        super().clear()
        self.decoder = URDecoder()
        self.received_parts = 0
        self.last_received_part = None

    def estimated_percent_complete(self):
        return self.decoder.estimated_percent_complete()


class MetaDataHandler:
    "Unified class to handle animated and static qr codes"

    def __init__(self, network) -> None:
        self.network = network
        # SinglePassCollector must be the last one
        self.collectors: List[BaseCollector] = [
            URCollector(self.network),
            SpecterDIYCollector(self.network),
            SinglePassCollector(self.network),
        ]
        self.last_used_collector = None

    def set_network(self, network: bdk.Network):
        self.network = network
        for collector in self.collectors:
            collector.network = network

    def get_collector(self, s: str):
        for collector in self.collectors:
            if collector.is_correct_data_format(s):
                return collector

    def add(self, s: str):
        self.last_used_collector = self.get_collector(s)
        return self.last_used_collector.add(s)

    def is_complete(self) -> bool:
        return self.last_used_collector.is_complete()

    def get_complete_data(self) -> Data:
        data = self.last_used_collector.get_complete_data()
        self.last_used_collector.clear()
        return data

    def estimated_percent_complete(self):
        if not self.last_used_collector:
            return 0
        return self.last_used_collector.estimated_percent_complete()
