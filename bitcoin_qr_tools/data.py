import base64
import enum
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from decimal import Decimal
from os import fdopen
from typing import Any, Dict, List, Optional, Union

import base58
import bdkpython as bdk

from bitcoin_qr_tools.converter_xpub import ConverterXpub
from bitcoin_qr_tools.i18n import translate
from bitcoin_qr_tools.signer_info import SignerInfo
from bitcoin_qr_tools.utils import (
    DecodingException,
    InconsistentDescriptors,
    InvalidBitcoinURI,
    WrongNetwork,
    serialized_to_hex,
)

from .multipath_descriptor import MultipathDescriptor

BITCOIN_BIP21_URI_SCHEME = "bitcoin"
logger = logging.getLogger(__name__)


class DataType(enum.Enum):
    Bip21 = enum.auto()  # https://bips.dev/21/
    Descriptor = enum.auto()
    MultiPathDescriptor = enum.auto()
    Xpub = enum.auto()
    Fingerprint = enum.auto()
    SignerInfo = enum.auto()  # FingerPrint, Derivation path, Xpub
    PSBT = enum.auto()
    Txid = enum.auto()
    Tx = enum.auto()
    SignerInfos = (
        enum.auto()
    )  # a list of SignerInfo with matching fingerprints (fingerprint, means here the root fingerprint)
    LabelsBip329 = enum.auto()
    UnrelatedSignerInfos = (
        enum.auto()
    )  # a list of SignerInfo, that do not (necessarily share the root fingerprint)
    MultisigWalletExport = enum.auto()

    @classmethod
    def from_value(cls, value: int) -> "DataType":
        min_value = min([member.value for member in cls])
        return list(cls)[value - min_value]

    @classmethod
    def from_name(cls, value: str) -> "DataType":
        names = [member.name for member in cls]
        return list(cls)[names.index(value)]


class ConverterTools:
    @classmethod
    def base43_decode(cls, v: str):
        "here is the simplified electrum base43 code"
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

    @classmethod
    def _decoding_strategies(cls):
        return [
            lambda x: base64.b64decode(x),  # base64 decoding
            lambda x: bytes.fromhex(x),  # hex decoding
            lambda x: cls.base43_decode(x),  # base43 decoding
            lambda x: base58.b58decode(x),
        ]


class ConverterTxid:
    @classmethod
    def is_valid_bitcoin_hash(cls, hash: str) -> bool:
        import re

        if re.match("^[a-f0-9]{64}$", hash):
            return True
        else:
            return False


class ConverterFingerprint:
    @classmethod
    def is_valid_wallet_fingerprint(cls, fingerprint: str) -> bool:
        import re

        if re.match("^[a-fA-F0-9]{8}$", fingerprint):
            return True
        else:
            return False


class ConverterAddress:
    @classmethod
    def is_bitcoin_address(cls, s, network: bdk.Network):
        try:
            bdkaddress = bdk.Address(s, network)
            return bool(bdkaddress) and bdkaddress.is_valid_for_network(network=network)
        except:
            return False


@dataclass
class ConverterMultisigWalletExport:
    name: str
    threshold: int
    address_type_short_name: str
    signer_infos: List[SignerInfo]

    def to_str(self) -> str:
        return self.to_custom_str(hardware_signer_name="")

    def to_custom_str(self, hardware_signer_name="Passport") -> str:
        return f"""# {hardware_signer_name} Multisig setup file (created by Bitcoin Safe)
#
Name: {self.name}
Policy: {self.threshold} of {len(self.signer_infos)}
Format: {self.address_type_short_name.upper()}

""" + "\n".join(
            [
                f"Derivation: {spk_provider.key_origin}\n{spk_provider.fingerprint}: {spk_provider.xpub}"
                for spk_provider in self.signer_infos
            ]
        )

    @classmethod
    def parse_from_legacy_coldcard(
        cls, s: str, network: bdk.Network
    ) -> "Optional[ConverterMultisigWalletExport]":
        """

        Can parse a string like
            # Exported by Blockstream Jade
            Name: hwi3374c2e55c4b
            Policy: 2 of 3
            Format: P2WSH
            Derivation: m/48'/1'/0'/2'
            14c949b4: tpubDDvtDSGt5JmgxgpRp3nyZj3ULZvFWuU9AaS6x3UwkNE6vaNgzd6oyKYEQUzSevUQs2ste5QznpbN8Nt5bVbZvrJFpCqw9UPXCtnCutEvEwW
            Derivation: m/48'/1'/0'/2'
            d8cf7475: tpubDEDUiUcwmoC92QJ2kGPQwtikGqLrjdyUfuRMhm5ab4nYmgRkkKPF9mp2FcunzMu9y5Ea2urGUJh4t1o7Wb6KjKddzJKcE8BoAyTWK6ughFK
            Derivation: m/48'/1'/0'/2'
            d5b43540: tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF"


        Args:
            s (str): _description_
            network (bdk.Network): _description_

        Returns:
            Optional[ConverterWalletExport]: _description_
        """
        lines = s.split("\n")

        def extract_value(line: str, key: str) -> Optional[str]:
            if line.startswith(key):
                return line[len(key) :].strip()
            return None

        def extract_unique(key: str) -> Optional[str]:
            for line in lines:
                res = extract_value(line, key=key)
                if res:
                    return res
            return None

        name = extract_unique("Name:")
        if not name:
            return None

        policy = extract_unique("Policy:")
        if not policy:
            return None
        if not " of " in policy:
            return None
        policy_parts = policy.split(" of ")
        if len(policy_parts) != 2:
            return None
        _threshold, _num_signers = policy_parts
        try:
            threshold = int(_threshold.strip())
            num_signers = int(_num_signers.strip())
        except:
            return None
        if not (0 < threshold <= num_signers):
            return None

        format = extract_unique("Format:")
        if not format:
            return None
        address_type_short_name = format.strip().lower()

        current_derivation = None
        # get the signer_infos
        signer_infos: List[SignerInfo] = []
        for line in lines:
            if line.startswith("#"):
                continue

            # if it is a derivation line
            if this_derivation := extract_value(line, "Derivation:"):
                current_derivation = this_derivation

            # if it is a fingerprint
            if not ":" in line:
                continue
            parts = line.split(":")
            if len(parts) != 2:
                continue
            first, last = parts
            if not ConverterFingerprint.is_valid_wallet_fingerprint(first):
                continue

            fingerprint = first.strip()

            last = last.strip()
            if not ConverterXpub.is_xpub(last):
                continue
            if not ConverterXpub.xpub_matches_network(last, network=network):
                raise WrongNetwork(f"xpub doesnt match network {network.name}")
            xpub = last

            #  ensure that current_derivation is set
            if not current_derivation:
                continue

            signer_infos.append(SignerInfo(xpub=xpub, fingerprint=fingerprint, key_origin=current_derivation))

        if not signer_infos or num_signers != len(signer_infos):
            return None

        return ConverterMultisigWalletExport(
            name=name,
            threshold=threshold,
            address_type_short_name=address_type_short_name,
            signer_infos=signer_infos,
        )


class ConverterBip329:
    @classmethod
    def is_ndjson_with_keys(cls, s: str, keys: List[str]):
        """
        Checks if the input string s is newline-delimited JSON and each JSON object contains the specified keys.

        Args:
        s (str): The input string to check.
        keys (list of str): The keys that must be present in each JSON object.

        Returns:
        bool: True if the string is newline-delimited JSON and each object contains the specified keys, False otherwise.
        """
        lines = s.splitlines()

        # Check if there's at least one line
        if not lines:
            return False

        for line in lines:
            try:
                obj = json.loads(line)
                # Check if all specified keys are present in the JSON object
                if not all(key in obj for key in keys):
                    logger.debug(f"ndjson check: Not all required keys {keys} are present in {obj}")
                    return False
            except json.JSONDecodeError:
                return False

        return True

    @classmethod
    def is_bip329(cls, s: str) -> bool:
        try:
            return cls.is_ndjson_with_keys(s, keys=["type", "ref", "label"])
        except:
            return False


class ConverterBip21:
    def __init__(self, data: Dict) -> None:
        self.data = data

    def to_json(self):
        return json.dumps(self.data)

    @classmethod
    def decode_bip21_uri(cls, uri: str, network: bdk.Network) -> dict:
        """Raises InvalidBitcoinURI on malformed URI."""
        TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 21000000
        COIN = 100000000

        if not isinstance(uri, str):
            raise InvalidBitcoinURI(f"expected string, not {repr(uri)}")

        if ":" not in uri:
            if ConverterAddress.is_bitcoin_address(uri, network=network):
                return {"address": uri}
            else:
                raise InvalidBitcoinURI("Not a bitcoin address")

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

        out: Dict[str, Any] = {k: v[0] for k, v in pq.items()}
        if address:
            if not ConverterAddress.is_bitcoin_address(address, network=network):
                raise InvalidBitcoinURI(f"Invalid bitcoin address: {address}")
            out["address"] = address
        if "amount" in out:
            am = out["amount"]
            try:
                m = re.match(r"([0-9.]+)X([0-9])", am)
                if m:
                    amount = Decimal(m.group(1)) * pow(Decimal(10), int(m.group(2)) - 8)
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

        return out

    @classmethod
    def _try_decode_bip21(cls, s, network: bdk.Network):
        try:
            return cls.decode_bip21_uri(s, network=network)
        except Exception:
            pass


class ConverterTx:
    def __init__(self, tx: bdk.Transaction) -> None:
        self.tx = tx

    def to_str(self):
        return str(serialized_to_hex(self.tx.serialize()))

    @classmethod
    def _try_transaction_binary(cls, raw: bytes) -> Optional[bdk.Transaction]:
        # Try each decoding strategy in the loop
        try:
            return bdk.Transaction(raw)
        except Exception:
            return None

    @classmethod
    def _try_decode_serialized_transaction(cls, s: str) -> Optional[bdk.Transaction]:
        # Try each decoding strategy in the loop
        for decode in ConverterTools._decoding_strategies():
            try:
                decoded = decode(s)
                return bdk.Transaction(decoded)
            except Exception:
                continue  # If one strategy fails, try the next

        return None


class ConverterPSBT:
    def __init__(self, psbt: bdk.PartiallySignedTransaction) -> None:
        self.psbt = psbt

    def to_str(self):
        return str(self.psbt.serialize())

    @classmethod
    def _try_decode_psbt_binary(cls, raw: bytes) -> Optional[bdk.PartiallySignedTransaction]:
        psbt_magic_bytes = b"psbt\xff"

        # Try each decoding strategy in the loop
        try:
            if raw[: len(psbt_magic_bytes)] == psbt_magic_bytes:
                return bdk.PartiallySignedTransaction(base64.b64encode(raw).decode())
        except Exception:
            return None
        return None

    @classmethod
    def _try_decode_psbt(cls, s) -> Optional[bdk.PartiallySignedTransaction]:
        psbt_magic_bytes = b"psbt\xff"

        # Try each decoding strategy in the loop
        for decode in ConverterTools._decoding_strategies():
            try:
                decoded = decode(s)
                if decoded[:5] == psbt_magic_bytes:
                    return bdk.PartiallySignedTransaction(base64.b64encode(decoded).decode())
            except Exception:
                continue  # If one strategy fails, try the next

        return None


class ConverterSignerInfo:
    def __init__(self, info: SignerInfo) -> None:
        self.data = info

    def to_json(self):
        return self.data.to_json()

    @classmethod
    def _try_extract_signer_info(cls, s: str) -> Optional[SignerInfo]:
        signer_info = None
        try:
            signer_info = SignerInfo.from_str(s)
        except:
            pass

        if signer_info:
            signer_info.xpub = ConverterXpub.normalized_to_bip32(signer_info.xpub)
            return signer_info

        # try to load from a generic json (and cobo)
        try:
            d = json.loads(s)
            fingerprint = None
            key_origin = None
            xpub = None
            derivation_path = None
            if d.get("fingerprint"):
                fingerprint = d.get("fingerprint")
            if d.get("xfp"):
                fingerprint = d.get("xfp")
            if d.get("key_origin"):
                key_origin = d.get("key_origin")
            if d.get("deriv"):
                key_origin = d.get("deriv")
            if d.get("path"):
                # cobo convention
                key_origin = d.get("path")
            if d.get("xpub"):
                xpub = d.get("xpub")
            if d.get("derivation_path"):
                derivation_path = d.get("derivation_path")
            if fingerprint and key_origin and xpub:
                return SignerInfo(
                    fingerprint=fingerprint, key_origin=key_origin, xpub=xpub, derivation_path=derivation_path
                )
        except Exception:
            pass

        return None


class ConverterSignerInfos:
    def __init__(self, infos: List[SignerInfo], network: bdk.Network) -> None:
        self.data = infos
        self.network = network

    @classmethod
    def _try_multisig_wallet_export(
        cls, s: str, network: bdk.Network
    ) -> Optional[ConverterMultisigWalletExport]:
        """_summary_

        Args:
            s (str): _description_
            network (bdk.Network): _description_

        Raises:
            e: WrongNetwork, if the format is correct, but it is WrongNetwork

        Returns:
            Optional[ConverterMultisigWalletExport]: _description_
        """
        try:
            return ConverterMultisigWalletExport.parse_from_legacy_coldcard(s, network=network)
        except Exception as e:
            if isinstance(e, WrongNetwork):
                raise e
        return None

    def sparrow_format(self) -> str:
        first_signer_info = self.data[0]
        assert isinstance(first_signer_info, SignerInfo)

        d: Dict[str, Any] = {
            "chain": "BTC"
            if self.network
            in [
                bdk.Network.BITCOIN,
            ]
            else "XRT",
            "xfp": first_signer_info.fingerprint,  # root fingerprint
        }

        for i, signer_info in enumerate(self.data):
            assert isinstance(signer_info, SignerInfo)
            assert first_signer_info.fingerprint == signer_info.fingerprint, translate(
                "data",
                "The fingerprints differ.  Only same fingerprints are supported, ensuring all derived keys belong to the same signer!",
            )

            key = signer_info.name if signer_info.name and (signer_info.name not in d) else str(i)
            d[key] = {
                "xpub": signer_info.xpub,
                # "xfp" :  do not give here the fingerprint, because the the sparrow format assumes the fingerprint at this derived key, rather than the root_fingerprint
                "deriv": signer_info.key_origin,
                "first": signer_info.first_address,
                "name": signer_info.name,
            }
        return json.dumps(d)

    @classmethod
    def _try_extract_sparrow_signer_infos(cls, s, network: bdk.Network) -> Optional[List[SignerInfo]]:
        # if it is a json
        json_data = None
        try:
            json_data = json.loads(s)

            # check if it is in sparrow export format
            assert "chain" in json_data
            assert "xfp" in json_data
            # assert "xpub" in json_data  # this is not necessarily always known
        except:
            return None

        if network == bdk.Network.BITCOIN:
            if json_data["chain"] != "BTC":
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")
        if network == bdk.Network.REGTEST:
            if json_data["chain"] not in ["XRT", "TBTC"]:  # XTR is coinkite
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")
        if network == bdk.Network.TESTNET:
            if json_data["chain"] not in ["XTN", "TBTC"]:  # XTN is coinkite
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")
        if network == bdk.Network.SIGNET:
            # unclear which chain value is used for signet in coldcard
            # https://coldcard.com/docs/upgrade/#mk4-version-511-feb-27-2023
            if json_data["chain"] not in ["XTN", "XRT", "TBTC"]:
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")

        # the fingerprint in the top level is the relevant one
        fingerprint = json_data["xfp"]

        return [
            SignerInfo(
                xpub=v["xpub"],
                fingerprint=fingerprint,
                key_origin=v["deriv"],
                first_address=v["first"] if "first" in v else None,
                name=v["name"],
            )
            for v in json_data.values()
            if isinstance(v, dict)
        ]

    @classmethod
    def _try_extract_multisig_signer_infos_coldcard_and_passport_qr(
        cls, s, network: bdk.Network
    ) -> Optional[List[SignerInfo]]:
        # if it is a json
        json_data = None
        try:
            json_data = json.loads(s)

            # check if it is in coldcard export format
            assert "xfp" in json_data
            # for coldcard  assert "account" in json_data
            # for passport  assert "account" not in json_data

        except Exception:
            return None

        # the fingerprint in the top level is the relevant one
        fingerprint = json_data["xfp"]

        # get all the main keys (address type names) by looking at which end with _deriv
        address_type_names = [key.rstrip("_deriv") for key in json_data if key.endswith("_deriv")]

        signer_infos = [
            SignerInfo(
                xpub=ConverterXpub.normalized_to_bip32(json_data[address_type_name]),
                fingerprint=fingerprint,
                key_origin=json_data[address_type_name + "_deriv"],
                name=address_type_name,
            )
            for address_type_name in address_type_names
        ]
        for signer_info in signer_infos:
            ConverterXpub.ensure_xpub_matches_network(signer_info.xpub, network=network)
        return signer_infos


class ConverterDescriptor:
    def __init__(self, descriptor: Union[bdk.Descriptor, MultipathDescriptor]) -> None:
        self.descriptor = descriptor

    def to_str(self):
        return self.descriptor.as_string_private()

    @classmethod
    def _try_get_descriptor(cls, s, network: bdk.Network) -> Optional[bdk.Descriptor]:
        try:
            assert "<" not in s, "This contains characters of a multipath descriptor"
            assert ">" not in s, "This contains characters of a multipath descriptor"
            descriptor = bdk.Descriptor(s, network)
            if descriptor:
                logger.debug("detected descriptor")
                return descriptor
        except Exception:
            pass

        try:
            specter_dict = json.loads(s)
            if "descriptor" in specter_dict:
                return cls._try_get_descriptor(specter_dict["descriptor"], network=network)
        except Exception:
            pass
        return None

    @classmethod
    def _try_get_multipath_descriptor(cls, s, network: bdk.Network) -> Optional[MultipathDescriptor]:
        # if new lines are presnt, try checking if there are descriptors in the lines
        if "\n" in s:
            splitted_lines = s.split("\n")
            raw_results = [
                cls._try_get_multipath_descriptor(line.strip(), network) for line in splitted_lines
            ]
            # check that all entries return the same multipath descriptor
            # "None" entries are disallowed, to ensure that no deception is possible
            results = [r for r in raw_results if r]
            if results == raw_results:
                all_identical = all(
                    element.as_string_private() == results[0].as_string_private() for element in results
                )
                if all_identical:
                    return results[0]
                else:
                    # the string contins multiple inconsitent descriptors.
                    # Don't know how to handle this properly.
                    raise InconsistentDescriptors(f"The descriptors {splitted_lines} are inconsistent.")
            else:
                # if splitting lines didnt work, then remove the \n and try to recognize all as 1 descriptor
                s = s.replace("\n", "")

        try:
            multipath_descriptor = MultipathDescriptor.from_descriptor_str(s, network)
            if multipath_descriptor:
                logger.debug("detected descriptor")
                return multipath_descriptor
        except Exception:
            pass
        return None


class Data:
    """
    Recognized bitcoin data in a string, gives the data and the DataType
    """

    def __init__(self, data, data_type: DataType, network: bdk.Network) -> None:
        self.data = data
        self.data_type = data_type
        self.network = network

    def dump(self) -> Dict:
        return {"data": self.data_as_string(), "data_type": self.data_type.name}

    @classmethod
    def from_dump(cls, d: Dict, network: bdk.Network) -> "Data":
        data = cls.from_str(d["data"], network=network)
        d["data_type"] = DataType.from_name(d["data_type"])
        assert d["data_type"] == data.data_type
        return data

    def data_as_string(self) -> str:
        if not self.data:
            return str(self.data)
        if isinstance(self.data, str):
            return self.data
        if self.data_type == DataType.Bip21:
            return ConverterBip21(data=self.data).to_json()
        if self.data_type == DataType.Descriptor:
            return ConverterDescriptor(descriptor=self.data).to_str()
        if self.data_type == DataType.MultiPathDescriptor:
            return ConverterDescriptor(descriptor=self.data).to_str()
        if self.data_type == DataType.SignerInfo:
            return ConverterSignerInfo(info=self.data).to_json()
        if self.data_type == DataType.SignerInfos:
            return ConverterSignerInfos(infos=self.data, network=self.network).sparrow_format()
        if self.data_type == DataType.PSBT:
            return ConverterPSBT(psbt=self.data).to_str()
        if self.data_type == DataType.Tx:
            return ConverterTx(tx=self.data).to_str()
        if self.data_type == DataType.MultisigWalletExport and isinstance(
            self.data, ConverterMultisigWalletExport
        ):
            return self.data.to_str()

        return str(self.data)

    def __str__(self) -> str:
        return f"{self.data_type.name}: {self.data_as_string()}"

    @classmethod
    def from_binary(cls, raw: bytes, network: bdk.Network) -> "Data":
        # # Sequence of checks to identify the type of data in `s`
        # if decoded_bip21 := cls._try_decode_bip21(s, network=network):
        #     return Data(decoded_bip21, DataType.Bip21)

        # if is_xpub(s):
        #     data = convert_slip132_to_bip32(s) if is_slip132(s) else s
        #     return Data(data, DataType.Xpub)

        # if descriptor := cls._try_get_descriptor(s, network):
        #     return Data(descriptor, DataType.Descriptor)

        # if descriptor := cls._try_get_multipath_descriptor(s, network):
        #     return Data(descriptor, DataType.MultiPathDescriptor)

        # if is_valid_bitcoin_hash(s):
        #     return Data(s, DataType.Txid)

        # if is_valid_wallet_fingerprint(s):
        #     return Data(s, DataType.Fingerprint)

        if psbt := ConverterPSBT._try_decode_psbt_binary(raw):
            return Data(psbt, DataType.PSBT, network=network)

        if tx := ConverterTx._try_transaction_binary(raw):
            return Data(tx, DataType.Tx, network=network)

        # if signer_info := cls._try_extract_signer_info(s, network):
        #     return Data(signer_info, DataType.SignerInfo)

        # if signer_infos := cls._try_extract_signer_infos(s, network):
        #     return Data(signer_infos, DataType.SignerInfos)

        # if is_bip329(s):
        #     return Data(s, DataType.LabelsBip329)

        raise DecodingException(f"{raw} Could not be decoded with from_binary")  # type: ignore

    @classmethod
    def from_tx(cls, tx: bdk.Transaction, network: bdk.Network) -> "Data":
        assert isinstance(tx, bdk.Transaction)
        return Data(tx, DataType.Tx, network=network)

    @classmethod
    def from_psbt(cls, psbt: bdk.PartiallySignedTransaction, network: bdk.Network) -> "Data":
        assert isinstance(psbt, bdk.PartiallySignedTransaction)
        return Data(psbt, DataType.PSBT, network=network)

    @classmethod
    def from_descriptor(cls, descriptor: bdk.Descriptor, network: bdk.Network) -> "Data":
        assert isinstance(descriptor, bdk.Descriptor)
        return Data(descriptor, DataType.Descriptor, network=network)

    @classmethod
    def from_multipath_descriptor(
        cls, multipath_descriptor: MultipathDescriptor, network: bdk.Network
    ) -> "Data":
        assert isinstance(multipath_descriptor, MultipathDescriptor)
        return Data(multipath_descriptor, DataType.MultiPathDescriptor, network=network)

    @classmethod
    def from_str(cls, s: str, network: bdk.Network) -> "Data":
        s = s.strip()
        data = None

        # Sequence of checks to identify the type of data in `s`
        if decoded_bip21 := ConverterBip21._try_decode_bip21(s, network=network):
            return Data(decoded_bip21, DataType.Bip21, network=network)

        if ConverterXpub.is_xpub(s):
            data = ConverterXpub.normalized_to_bip32(s)
            return Data(data, DataType.Xpub, network=network)

        if descriptor := ConverterDescriptor._try_get_descriptor(s, network):
            return Data(descriptor, DataType.Descriptor, network=network)

        if descriptor := ConverterDescriptor._try_get_multipath_descriptor(s, network):
            return Data(descriptor, DataType.MultiPathDescriptor, network=network)

        if ConverterTxid.is_valid_bitcoin_hash(s):
            return Data(s, DataType.Txid, network=network)

        if ConverterFingerprint.is_valid_wallet_fingerprint(s):
            return Data(s, DataType.Fingerprint, network=network)

        if psbt := ConverterPSBT._try_decode_psbt(s):
            return Data(psbt, DataType.PSBT, network=network)

        if tx := ConverterTx._try_decode_serialized_transaction(s):
            return Data(tx, DataType.Tx, network=network)

        if signer_info := ConverterSignerInfo._try_extract_signer_info(s):
            return Data(signer_info, DataType.SignerInfo, network=network)

        if signer_infos := ConverterSignerInfos._try_extract_sparrow_signer_infos(s, network):
            return Data(signer_infos, DataType.SignerInfos, network=network)

        if signer_infos := ConverterSignerInfos._try_extract_multisig_signer_infos_coldcard_and_passport_qr(
            s, network
        ):
            return Data(signer_infos, DataType.SignerInfos, network=network)

        if ConverterBip329.is_bip329(s):
            return Data(s, DataType.LabelsBip329, network=network)

        if wallet_export := ConverterSignerInfos._try_multisig_wallet_export(s, network=network):
            # this is the Multisig wallet export of jade, and the signers (of course)  are different
            return Data(wallet_export, DataType.MultisigWalletExport, network=network)

        raise DecodingException(f"{s} Could not be decoded with from_str")

    def write_to_filedescriptor(self, fd):
        """

        This is useful for a temporary file
        fd, file_path = tempfile.mkstemp(
            suffix=f"_{key}.{self.file_extension}", prefix=""
        )

        a file descriptor for a normal file can be created with
                fd = os.open(filename, os.O_CREAT | os.O_WRONLY)
        """
        if self.data_type == DataType.Tx:
            with fdopen(fd, "wb") as file:
                file.write(bytes(self.data.serialize()))
        elif self.data_type == DataType.PSBT:
            with fdopen(fd, "wb") as file:
                file.write(base64.b64decode(self.data.serialize()))
        else:
            with fdopen(fd, "w") as file:
                file.write(self.data_as_string())
