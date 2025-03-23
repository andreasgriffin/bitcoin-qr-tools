import json
import logging
from dataclasses import dataclass
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class SignMessageRequest:
    """
    Example {"msg":"test message", "subpath": "m/84h/0h/0h/0/10","addr_fmt": "p2wpkh"}
    See: https://coldcard.com/docs/message-signing/
    """

    msg: str
    subpath: str
    addr_fmt: str

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__dict__})"

    def __str__(self) -> str:
        return f"{self.__dict__}"

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    def dict(self) -> Dict:
        return self.__dict__

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__
