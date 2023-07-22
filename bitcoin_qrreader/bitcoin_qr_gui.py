from .qr_qui import VideoWidget
from .bitcoin_qr import *
from PySide2 import QtWidgets
from typing import Dict
import pygame, math


class BitcoinVideoWidget(VideoWidget):
    def __init__(
        self,
        result_callback=None,
        close_on_result=True,
        parent=None,
        network=bdk.Network.REGTEST,
    ):
        super().__init__(qr_data_callback=self.qr_data_callback, parent=parent)

        self.network = network
        self.result_callback = result_callback
        self.close_on_result = close_on_result

        self.meta_data_handler = MetaDataHandler(self.network)

    def qr_data_callback(self, qr_data):
        self.meta_data_handler.add(qr_data.decode("utf-8"))

        if self.meta_data_handler.is_complete():
            if self.close_on_result:
                self.close()
            if self.result_callback:
                self.result_callback(self.meta_data_handler.get_complete_data())

    def on_draw_surface(self, surface, barcode):
        super().on_draw_surface(surface, barcode)

        estimated_percent_complete = self.meta_data_handler.estimated_percent_complete()
        if 0 == estimated_percent_complete:
            return

        x, y, w, h = barcode.rect
        y_new = x
        x_new = y

        # Draw a filled arc (which is actually a filled pie slice)
        center_x = x_new + w // 2
        center_y = y_new + h // 2
        radius = min(w, h) // 4  # Radius should not exceed the rectangle
        start_angle = -math.pi  # For example
        stop_angle = -math.pi - math.pi * 2 * estimated_percent_complete

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


class DemoBitcoinVideoWidget(BitcoinVideoWidget):
    def __init__(
        self,
        parent=None,
        close_on_result=False,
    ):
        super().__init__(
            result_callback=self.result_callback,
            parent=parent,
            close_on_result=close_on_result,
        )

        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)

    def result_callback(self, qr_data):
        self.label_qr.setText(str(qr_data))
