import base64
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

import bdkpython as bdk

from bitcoin_qr_tools.data import Data

from .ur.ur_decoder import URDecoder
from .urtypes.bytes import Bytes as UR_BYTES
from .urtypes.crypto import PSBT as UR_PSBT
from .urtypes.crypto import Output as US_OUTPUT

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    def __init__(self, network) -> None:
        self.data: Optional[Data] = None
        self.network = network

    @abstractmethod
    def is_correct_data_format(self, s):
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
    def is_correct_data_format(self, s):
        return True

    def is_complete(self) -> bool:
        return bool(self.data)

    def get_complete_data(self) -> Optional[Data]:
        return self.data

    def add(self, s: str) -> Data:
        self.data = Data.from_str(s, network=self.network)
        return self.data

    def estimated_percent_complete(self):
        return float(bool(self.data))


class SpecterDIYCollector(BaseCollector):
    def __init__(self, network) -> None:
        super().__init__(network)
        self.clear()
        self.total_parts: int = 0

    def is_correct_data_format(self, s):
        return self.extract_specter_diy_qr_part(s) is not None

    def is_complete(self) -> bool:
        return len(self.parts) == self.total_parts

    def get_complete_data(self) -> Optional[Data]:
        if not self.is_complete():
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

    def is_psbt(self, s: str):
        return re.search("^UR:CRYPTO-PSBT/", s, re.IGNORECASE)

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

    def add(self, s: str) -> Optional[str]:
        self.decoder.receive_part(s)
        logger.debug(f"{round(self.decoder.estimated_percent_complete()*100)}% complete")

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
        return len(self.decoder.received_part_indexes()) / self.decoder.expected_part_count()


class UnifiedDecoder:
    "Unified class to handle animated and static qr codes"

    def __init__(self, network) -> None:
        self.network = network
        # SinglePassCollector must be the last one
        self.collectors: List[BaseCollector] = [
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
