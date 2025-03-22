import logging

from bitcoin_qr_tools.data import DecodingException

logger = logging.getLogger(__name__)

import bdkpython as bdk
import pygame
from PyQt6 import QtWidgets
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut

from bitcoin_qr_tools.unified_decoder import UnifiedDecoder

from ..data import Data
from .video_widget import BarcodeData, VideoWidget


class BitcoinVideoWidget(VideoWidget):
    signal_data = pyqtSignal(Data)
    signal_raw_decoded = pyqtSignal(object)
    signal_recognize_exception = pyqtSignal(Exception)

    def __init__(
        self,
        close_on_result=True,
        parent=None,
        network=bdk.Network.REGTEST,
        show_network_switch=False,
    ):
        super().__init__(parent=parent)
        self.network: bdk.Network = network
        # self.last_barcode_rect = (0,0,0,0)
        # self.frames_since_last_barcode = 0

        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self._layout.insertWidget(1, self.progress_bar)

        self.combo_network = QtWidgets.QComboBox(self)
        self.combo_network.addItems([n.name for n in bdk.Network])
        self.combo_network.setCurrentText(self.network.name)
        self._layout.addWidget(self.combo_network)
        self.combo_network.setVisible(show_network_switch)

        self.close_on_result = close_on_result

        self.meta_data_handler = UnifiedDecoder(self.network)
        self.switch_network([n.name for n in bdk.Network].index(self.network.name))
        self.combo_network.currentIndexChanged.connect(self.switch_network)
        self.signal_raw_qr_data.connect(self.on_raw_qr_data)

        self.shortcut_close = QShortcut(QKeySequence("Ctrl+W"), self)
        self.shortcut_close.activated.connect(self.close)
        self.shortcut_close2 = QShortcut(QKeySequence("ESC"), self)
        self.shortcut_close2.activated.connect(self.close)

    def switch_network(self, idx):
        networks = [n for n in bdk.Network]
        self.meta_data_handler.set_network(networks[idx])

    def on_raw_qr_data(self, qr_data):
        try:
            self.meta_data_handler.add(qr_data.decode("utf-8"))
        except DecodingException as e:
            logger.warning(str(e))

        if self.meta_data_handler.is_complete():
            if self.close_on_result:
                self.close()

            try:
                raw = self.meta_data_handler.get_complete_raw_preserve_memory()
                self.signal_raw_decoded.emit(raw)
                data = self.meta_data_handler.get_complete_data()
                if data:
                    self.signal_data.emit(data)
            except Exception as e:
                logger.warning(f"Could not decode data.  {e}")
                self.signal_recognize_exception.emit(e)

    def set_progress_bar(self):
        estimated_percent_complete = self.meta_data_handler.estimated_percent_complete()
        self.progress_bar.setValue(int((estimated_percent_complete or 0) * 100))

    def _on_draw_surface(self, surface: pygame.Surface, barcode: BarcodeData):
        super()._on_draw_surface(surface, barcode)
        self.set_progress_bar()


class DemoBitcoinVideoWidget(BitcoinVideoWidget):
    def __init__(
        self,
        parent=None,
        close_on_result=False,
        network=bdk.Network.REGTEST,
    ):
        super().__init__(
            parent=parent,
            close_on_result=close_on_result,
            network=network,
            show_network_switch=True,
        )
        self.signal_data.connect(self.result_callback)
        self.signal_raw_decoded.connect(self.callback_raw)
        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)  # type: ignore

    def callback_raw(self, o: object):
        logger.info(f"Decoded raw: {o}")

    def result_callback(self, qr_data):
        new_text = str(qr_data)
        if self.label_qr.toPlainText() == new_text:
            return

        self.label_qr.setText(new_text)
