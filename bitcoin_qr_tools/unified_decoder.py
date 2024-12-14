import base64
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple

import bdkpython as bdk

from bitcoin_qr_tools import bbqr
from bitcoin_qr_tools.bbqr.consts import FILETYPE_NAMES, KNOWN_FILETYPES
from bitcoin_qr_tools.data import Data, DataType
from bitcoin_qr_tools.signer_info import SignerInfo
from bitcoin_qr_tools.ur_tools import URTools
from bitcoin_qr_tools.urtypes.crypto.account import CRYPTO_ACCOUNT
from bitcoin_qr_tools.urtypes.crypto.output import CRYPTO_OUTPUT
from bitcoin_qr_tools.urtypes.crypto.psbt import CRYPTO_PSBT

from .ur.ur_decoder import URDecoder
from .urtypes.bytes import BYTES
from .urtypes.bytes import Bytes as UR_BYTES
from .urtypes.crypto import PSBT as UR_PSBT
from .urtypes.crypto import Account as UR_ACCOUNT
from .urtypes.crypto import Output as UR_OUTPUT

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    def __init__(self, network) -> None:
        self.data: Optional[Data] = None
        self.network = network

    @abstractmethod
    def is_correct_data_format(self, s) -> bool:
        pass

    @abstractmethod
    def is_complete(self) -> bool:
        pass

    @abstractmethod
    def get_complete_data(self) -> Optional[Data]:
        pass

    @abstractmethod
    def add(self, s: str):
        pass

    def clear(self):
        self.data = None

    @abstractmethod
    def estimated_percent_complete(self):
        pass


class SinglePassCollector(BaseCollector):
    def is_correct_data_format(self, s) -> bool:
        return True

    def is_complete(self) -> bool:
        return bool(self.last)

    def get_complete_data(self) -> Optional[Data]:
        return Data.from_str(self.last, network=self.network)

    def add(self, s: str) -> str:
        self.last = s
        return self.last

    def estimated_percent_complete(self):
        return float(bool(self.data))


class SpecterDIYCollector(BaseCollector):
    def __init__(self, network) -> None:
        super().__init__(network)
        self.clear()
        self.total_parts: int | None = 0

    def is_correct_data_format(self, s) -> bool:
        return self.extract_specter_diy_qr_part(s) is not None

    def is_complete(self) -> bool:
        return len(self.parts) == self.total_parts

    def get_complete_data(self) -> Optional[Data]:
        if (self.total_parts is None) or not self.is_complete():
            return None

        total_s = ""
        for i in range(1, self.total_parts + 1):
            total_s += self.parts[i]
        return Data.from_str(total_s, network=self.network)

    def extract_specter_diy_qr_part(self, s) -> Optional[Tuple[int, int, str]]:
        "pMofM something  ->  (M,N,something)"
        pattern = r"^p(\d+)of(\d+)\s(.*)"
        match = re.match(pattern, s)
        if match:
            return int(match.group(1)), int(match.group(2)), match.group(3)
        return None

    def add(self, s: str) -> Optional[str]:
        specter_diy_qr_part = self.extract_specter_diy_qr_part(s)
        if not specter_diy_qr_part:
            return None
        m, n, data = specter_diy_qr_part
        if (self.total_parts is not None) and n != self.total_parts:
            # if n != self.total_parts then, it appears we switched to a different qrcode
            self.clear()

        if self.total_parts is None:
            self.total_parts = n

        self.parts[m] = data
        logger.debug(f"{self.__class__.__name__}: {round(self.estimated_percent_complete()*100)}% complete")
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
        self.last_received_part: Optional[str] = None
        # self.all_parts: List = []

    def is_psbt(self, s: str):
        return re.search(f"^UR:{CRYPTO_PSBT.type.upper()}/", s, re.IGNORECASE)

    def is_descriptor(self, s: str):
        return re.search(f"^UR:{CRYPTO_OUTPUT.type.upper()}/", s, re.IGNORECASE)

    def is_account(self, s: str):
        return re.search(f"^UR:{CRYPTO_ACCOUNT.type.upper()}/", s, re.IGNORECASE)

    def is_bytes(self, s: str):
        return re.search(f"^UR:{BYTES.type.upper()}/", s, re.IGNORECASE)

    def is_correct_data_format(self, s) -> bool:
        if self.is_psbt(s):
            return True
        if self.is_descriptor(s):
            return True
        if self.is_account(s):
            return True
        if self.is_bytes(s):
            return True

        return False

    def is_complete(self) -> bool:
        return self.decoder.is_complete()

    def get_complete_data(self) -> Data:
        if self.decoder.result.type == CRYPTO_OUTPUT.type:
            return Data(
                data=SignerInfo.decode_descriptor_as_signer_info(
                    UR_OUTPUT.from_cbor(self.decoder.result.cbor).descriptor(), network=self.network
                ),
                data_type=DataType.SignerInfo,
                network=self.network,
            )
        elif self.decoder.result.type == CRYPTO_ACCOUNT.type:
            return Data(
                data=URTools.decode_account_as_signer_infos(
                    UR_ACCOUNT.from_cbor(self.decoder.result.cbor), network=self.network
                ),
                data_type=DataType.SignerInfos,
                network=self.network,
            )
        elif self.decoder.result.type == CRYPTO_PSBT.type:
            qr_content = UR_PSBT.from_cbor(self.decoder.result.cbor).data
            s = base64.b64encode(qr_content).decode("utf-8")
        elif self.decoder.result.type == BYTES.type:
            raw = UR_BYTES.from_cbor(self.decoder.result.cbor).data
            try:
                # for UR text info
                s = raw.decode()
            except:
                # for UR tx
                s = raw.hex()

        return Data.from_str(s, network=self.network)

    def add(self, s: str) -> Optional[str]:
        self.decoder.receive_part(s)
        # self.all_parts.append(s)
        logger.debug(f"{self.__class__.__name__}: {round(self.estimated_percent_complete()*100)}% complete")

        # if the decoder is stuck for some reason. reset it
        # this part must be done AFTER receive_part(s)
        if self.received_parts > self.decoder.expected_part_count() * 2:
            logger.debug(
                f"{self.__class__.__name__}: {self.received_parts}/{self.decoder.expected_part_count()} parts received, but incomplete. Resetting"
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
        return len(self.decoder.received_part_indexes()) / self.decoder.expected_part_count()


class BBQRCollector(BaseCollector):
    def __init__(self, network) -> None:
        super().__init__(network)
        self.clear()

    def clear(self):
        super().clear()
        self.parts: Dict[int, str] = {}
        self.total_parts = None

    def is_correct_data_format(self, s) -> bool:
        if self.get_splitted_data(s):
            return True

        return False

    def get_splitted_data(self, part) -> Optional[Tuple[str, str, int, int, str]]:
        "validation. If invalid, returns None"
        try:
            assert part[0:2] == "B$", "fixed header not found, expected B$"
            encoding = part[2]
            file_type = part[3]
            num_parts = int(part[4:6], 36)

            assert num_parts >= 1, "zero parts?"
            assert encoding in "H2Z", f"bad encoding: {encoding}"
            assert file_type in KNOWN_FILETYPES, f"bad file type: {encoding}"

            idx = int(part[6:8], 36)

            assert idx < num_parts, f"got part {idx} but only expecting {num_parts}"

            raw = part[8:]
            return encoding, file_type, num_parts, idx, raw
        except:
            return None

    def get_available_indices(self) -> Set[int]:

        return set(self.parts.keys())

    def estimated_percent_complete(self):
        num_parts = self.total_parts
        if not num_parts:
            return 0
        return len(self.get_available_indices()) / num_parts

    def is_complete(self) -> bool:
        return self.estimated_percent_complete() >= 1

    def get_complete_data(self) -> Optional[Data]:
        if not self.is_complete():
            return None

        try:
            file_type, raw = bbqr.join_qrs(list(self.parts.values()))
        except:
            self.clear()
            return None

        if FILETYPE_NAMES[file_type] in ["Transaction", "Binary"]:
            return Data.from_binary(raw, network=self.network)
        if FILETYPE_NAMES[file_type] in ["PSBT"]:

            return Data.from_binary(raw, network=self.network)

        if FILETYPE_NAMES[file_type] in ["JSON", "Unicode Text"]:
            return Data.from_str(raw.decode(), network=self.network)

        return None

    def _are_consistent(self, *parts) -> bool:
        if not parts:
            return True
        meta_datas = [self.get_splitted_data(part) for part in parts]
        if not all(meta_datas):
            # Not a single one can be None
            return False

        for i in [0, 1, 2]:
            if len(set([meta_data[i] for meta_data in meta_datas if meta_data])) != 1:
                return False

        return True

    def add(self, s: str) -> Optional[str]:
        # only allow valid parts to be added
        if not self.is_correct_data_format(s):
            return None

        # compare with exising  meta data
        if self.parts:
            existing_part = list(self.parts.values())[0]
            if not self._are_consistent(existing_part, s):
                logger.debug(f"Clearing cache, because {existing_part} if inconsistent with {s}")
                self.clear()

        meta_data = self.get_splitted_data(s)
        if meta_data:
            encoding, file_type, num_parts, idx, raw = meta_data
            self.parts[idx] = s
            self.total_parts = num_parts

        logger.debug(f"{self.__class__.__name__}: {round(self.estimated_percent_complete()*100)}% complete")

        return s


class UnifiedDecoder:
    "Unified class to handle animated and static qr codes"

    def __init__(self, network) -> None:
        self.network = network
        # SinglePassCollector must be the last one
        self.collectors: List[BaseCollector] = [
            BBQRCollector(self.network),
            URCollector(self.network),
            SpecterDIYCollector(self.network),
            SinglePassCollector(self.network),
        ]
        self.last_used_collector: Optional[BaseCollector] = None

    def set_network(self, network: bdk.Network):
        self.network = network
        for collector in self.collectors:
            collector.network = network

    def get_collector(self, s: str) -> Optional[BaseCollector]:
        for collector in self.collectors:
            if collector.is_correct_data_format(s):
                return collector
        return None

    def add(self, s: str):
        self.last_used_collector = self.get_collector(s)
        if not self.last_used_collector:
            raise Exception("Could not get a fitting colletor")
        return self.last_used_collector.add(s)

    def is_complete(self) -> bool:
        if not self.last_used_collector:
            return False
        return self.last_used_collector.is_complete()

    def get_complete_data(self) -> Optional[Data]:
        if not self.last_used_collector:
            return None
        data = self.last_used_collector.get_complete_data()
        self.last_used_collector.clear()
        return data

    def estimated_percent_complete(self):
        if not self.last_used_collector:
            return 0
        return self.last_used_collector.estimated_percent_complete()
