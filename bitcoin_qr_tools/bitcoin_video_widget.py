import logging
import math

from bitcoin_qr_tools.data import DecodingException

logger = logging.getLogger(__name__)

import bdkpython as bdk
import pygame
from PyQt6 import QtWidgets

from bitcoin_qr_tools.unified_decoder import UnifiedDecoder

from .qr_qui import VideoWidget


class BitcoinVideoWidget(VideoWidget):
    def __init__(
        self,
        result_callback=None,
        close_on_result=True,
        parent=None,
        network=bdk.Network.REGTEST,
        show_network_switch=False,
    ):
        super().__init__(qr_data_callback=self.qr_data_callback, parent=parent)
        self.network: bdk.Network = network

        self.combo_network = QtWidgets.QComboBox(self)
        self.combo_network.addItems([n.name for n in bdk.Network])
        self.combo_network.setCurrentText(self.network.name)
        self.layout().addWidget(self.combo_network)
        self.combo_network.setVisible(show_network_switch)

        self.result_callback = result_callback
        self.close_on_result = close_on_result

        self.meta_data_handler = UnifiedDecoder(self.network)
        self.switch_network([n.name for n in bdk.Network].index(self.network.name))
        self.combo_network.currentIndexChanged.connect(self.switch_network)

    def switch_network(self, idx):
        networks = [n for n in bdk.Network]
        self.meta_data_handler.set_network(networks[idx])

    def qr_data_callback(self, qr_data):
        try:
            self.meta_data_handler.add(qr_data.decode("utf-8"))
        except DecodingException as e:
            logger.warning(str(e))

        if self.meta_data_handler.is_complete():
            if self.close_on_result:
                self.close()
            if self.result_callback:
                try:
                    self.result_callback(self.meta_data_handler.get_complete_data())
                except:
                    logger.warning(f"Could not decode data")

    def draw_pie_progress_bar(self, surface, rect, percentage, color):
        x, y, w, h = rect
        # Calculate the center and radius based on the barcode rectangle
        center_x, center_y = x + w / 2, y + h / 2
        radius = min(w, h) / 2  # Adjust the divisor as needed

        # Draw a filled arc (which is actually a filled pie slice)
        radius = min(w, h) // 4  # Radius should not exceed the rectangle
        start_angle = -math.pi  # For example
        stop_angle = -math.pi - math.pi * 2 * percentage

        # Draw lots of small lines to create the filled arc
        num_segments = 100  # Increase this for a smoother arc
        angle_step = (stop_angle - start_angle) / num_segments
        points = [(center_x, center_y)]
        for i in range(num_segments + 1):
            angle = start_angle + i * angle_step
            point_x = center_x + radius * math.cos(angle)
            point_y = center_y + radius * math.sin(angle)
            points.append((point_x, point_y))

        # Use pygame.draw.polygon to draw the filled arc
        pygame.draw.polygon(surface, (0, 255, 0), points)

    def _on_draw_surface(self, surface, barcode):
        super()._on_draw_surface(surface, barcode)

        estimated_percent_complete = self.meta_data_handler.estimated_percent_complete()
        print(estimated_percent_complete)
        if 0 == estimated_percent_complete:
            return

        self.draw_pie_progress_bar(surface, barcode.rect, estimated_percent_complete, (0, 255, 0))


class DemoBitcoinVideoWidget(BitcoinVideoWidget):
    def __init__(
        self,
        parent=None,
        close_on_result=False,
        network=bdk.Network.REGTEST,
    ):
        super().__init__(
            result_callback=self.result_callback,
            parent=parent,
            close_on_result=close_on_result,
            network=network,
            show_network_switch=True,
        )

        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)

    def result_callback(self, qr_data):
        self.label_qr.setText(str(qr_data))
