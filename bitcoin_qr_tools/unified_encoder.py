import base64
import logging
from dataclasses import dataclass
from typing import List

import bdkpython as bdk

from bitcoin_qr_tools.bbqr.split import split_qrs
from bitcoin_qr_tools.data import Data, DataType
from bitcoin_qr_tools.ur_tools import URTools
from bitcoin_qr_tools.urtypes.bytes import BYTES
from bitcoin_qr_tools.urtypes.crypto.output import CRYPTO_OUTPUT
from bitcoin_qr_tools.urtypes.crypto.psbt import CRYPTO_PSBT
from bitcoin_qr_tools.utils import hex_to_serialized

from .ur.cbor_lite import CBOREncoder
from .ur.ur import UR
from .ur.ur_encoder import UREncoder

logger = logging.getLogger(__name__)


@dataclass
class QrExportType:
    name: str
    display_name: str


class QrExportTypes:
    bbqr = QrExportType("bbqr", "BBQr")
    ur = QrExportType("ur", "UR")
    text = QrExportType("text", "Text")

    @classmethod
    def as_list(cls) -> List[QrExportType]:
        return [
            export_type for name, export_type in cls.__dict__.items() if isinstance(export_type, QrExportType)
        ]


class UnifiedEncoder:
    "Create animated and static qr codes"

    @classmethod
    def bytes_to_ur_byte_fragments(cls, encoded: bytes, type="bytes", max_qr_size=50) -> List[str]:
        bcor_encoder = CBOREncoder()
        bcor_encoder.encodeBytes(encoded)
        ur = UR(type, bcor_encoder.get_bytes())

        encoder = UREncoder(ur, max_fragment_len=max_qr_size)
        fragments = []
        while not encoder.is_complete():
            part = encoder.next_part()
            fragments.append(part)
        return fragments

    @classmethod
    def string_to_ur_byte_fragments(cls, string_data: str, max_qr_size=50) -> List[str]:
        return cls.bytes_to_ur_byte_fragments(string_data.encode(), type="bytes", max_qr_size=max_qr_size)

    @staticmethod
    def _max_qr_code_version(num_modules: int) -> int:
        """
        Determine the maximum QR code version based on the number of modules per side,
        returning the next lowest version if an exact match isn't found.

        This function adjusts for inputs that do not directly correspond to a specific QR code version,
        opting instead to return the highest version whose module count is less than or equal to the given number.

        The formula used is: version = (num_modules - 21) // 4 + 1

        Parameters:
        - num_modules (int): The number of modules per side of the QR code.

        Returns:
        - int: The maximum version of a QR code for which the module count per side is less than or equal to the provided number.

        The complete QR code version-to-modules mapping is:
        - Version 1: 21x21 modules
        - Version 2: 25x25 modules
        - Version 3: 29x29 modules
        - Version 4: 33x33 modules
        - Version 5: 37x37 modules
        - Version 6: 41x41 modules
        - Version 7: 45x45 modules
        - Version 8: 49x49 modules
        - Version 9: 53x53 modules
        - Version 10: 57x57 modules
        - Version 11: 61x61 modules
        - Version 12: 65x65 modules
        - Version 13: 69x69 modules
        - Version 14: 73x73 modules
        - Version 15: 77x77 modules
        - Version 16: 81x81 modules
        - Version 17: 85x85 modules
        - Version 18: 89x89 modules
        - Version 19: 93x93 modules
        - Version 20: 97x97 modules
        - Version 21: 101x101 modules
        - Version 22: 105x105 modules
        - Version 23: 109x109 modules
        - Version 24: 113x113 modules
        - Version 25: 117x117 modules
        - Version 26: 121x121 modules
        - Version 27: 125x125 modules
        - Version 28: 129x129 modules
        - Version 29: 133x133 modules
        - Version 30: 137x137 modules
        - Version 31: 141x141 modules
        - Version 32: 145x145 modules
        - Version 33: 149x149 modules
        - Version 34: 153x153 modules
        - Version 35: 157x157 modules
        - Version 36: 161x161 modules
        - Version 37: 165x165 modules
        - Version 38: 169x169 modules
        - Version 39: 173x173 modules
        - Version 40: 177x177 modules

        Example:
        - A QR code with 26 modules per side corresponds to Version 2 since it's the highest version not exceeding 26 modules.
        """
        if num_modules < 21:
            return 1

        # Calculate version based on the input module size.
        version = (num_modules - 21) // 4 + 1

        # Ensure the calculated version does not exceed the bounds of the QR specification (1 to 40).
        if version < 1:
            return 1
        elif version > 40:
            version = 40  # Cap the version at 40 if it exceeds the maximum.

        # Check if calculated version really matches the max version not exceeding the given module size.
        # This adjusts down if the input size does not perfectly align with the calculated version's expected size.
        if (21 + 4 * (version - 1)) > num_modules:
            version -= 1

        return version

    @classmethod
    def generate_fragments_for_qr(cls, data: Data, qr_export_type: QrExportType, max_qr_size=50) -> List[str]:
        if qr_export_type.name == QrExportTypes.text.name:
            return [data.data_as_string()]
        elif qr_export_type.name == QrExportTypes.ur.name:
            serialized = data.data_as_string()

            if len(serialized) <= max_qr_size:
                return [serialized]

            if data.data_type == DataType.Tx:
                return cls.bytes_to_ur_byte_fragments(
                    hex_to_serialized(serialized), type=BYTES.type, max_qr_size=max_qr_size
                )
            elif data.data_type == DataType.PSBT:
                return cls.bytes_to_ur_byte_fragments(
                    base64.b64decode(serialized.encode()), type=CRYPTO_PSBT.type, max_qr_size=max_qr_size
                )
            elif data.data_type == DataType.Descriptor:
                return cls.bytes_to_ur_byte_fragments(
                    URTools.encode_ur_output(descriptor_str=serialized).to_cbor(),
                    type=CRYPTO_OUTPUT.type,
                    max_qr_size=max_qr_size,
                )
            else:
                return cls.bytes_to_ur_byte_fragments(
                    serialized.encode(), type="bytes", max_qr_size=max_qr_size
                )

        elif qr_export_type.name == QrExportTypes.bbqr.name:
            if data.data_type == DataType.Tx:
                file_type = "T"
                assert isinstance(data.data, bdk.Transaction)
                raw = bytes(data.data.serialize())
            elif data.data_type == DataType.PSBT:
                file_type = "P"
                assert isinstance(data.data, bdk.PartiallySignedTransaction)
                raw = base64.b64decode(data.data.serialize())
            else:
                file_type = "U"
                raw = data.data_as_string().encode()

            version, parts = split_qrs(
                raw, file_type, max_version=cls._max_qr_code_version(num_modules=max_qr_size)
            )
            return parts

        raise Exception(f"Unknown qr_type {qr_export_type}")
