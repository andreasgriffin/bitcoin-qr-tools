import logging

logger = logging.getLogger(__name__)


import time
from typing import List, Tuple

import mss
import numpy as np
import pygame
import pygame.camera
from mss.base import MSSBase
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import pyqtSignal


class BarcodeData:
    def __init__(self, data, rect):
        self.data = data  # The decoded text of the barcode
        self.rect = rect  # The bounding rectangle of the barcode as a tuple (x, y, width, height)

    def __repr__(self):
        return f"BarcodeData(data={self.data}, rect={self.rect})"


class VideoWidget(QtWidgets.QWidget):
    signal_raw_qr_data = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cv2 = None
        self.pyzbar = None
        try:
            # check if loading works
            # it depend on zlib installed in the os
            from pyzbar import pyzbar

            self.pyzbar = pyzbar
            logger.info("Load pyzbar successful")
        except:
            logger.info("Could not load pyzbar. Trying to load fallback cv2")
            import cv2

            self.cv2 = cv2

        self.label_image = QtWidgets.QLabel()

        self.combo_cameras = QtWidgets.QComboBox()

        pygame.camera.init()
        for camera_name, camera in self.get_valid_cameras():
            self.combo_cameras.addItem(camera_name, userData=camera)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.label_image)
        layout.addWidget(self.combo_cameras)

        self.setLayout(layout)

        self.current_camera = None

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_frame)
        self.timer.start(int(1000.0 / 30.0))  # 30 FPS

        # Add "Screen" option for screen capture
        self.combo_cameras.addItem("Screen", userData=mss.mss())

        # switch to the last camera that isn
        if self.combo_cameras.count():
            last_camera_idx = max(self.combo_cameras.count() - 2, 0)
            self.combo_cameras.setCurrentIndex(last_camera_idx)
            self.switch_camera(last_camera_idx)

        # signals
        self.combo_cameras.currentIndexChanged.connect(self.switch_camera)

    def closeEvent(self, event: QtGui.QCloseEvent | None) -> None:
        self.timer.stop()
        if self.current_camera:
            try:
                self.current_camera.stop()
            except:
                pass

        # If you call the parent's closeEvent(), it will proceed to close the widget
        super().closeEvent(event)

    def get_valid_cameras(self) -> List[Tuple[str, pygame.camera.Camera]]:
        valid_cameras: List[Tuple[str, pygame.camera.Camera]] = []
        for camera_name in pygame.camera.list_cameras():
            try:
                temp_camera = pygame.camera.Camera(camera_name, (640, 480))
                temp_camera.start()
                temp_camera.stop()
                valid_cameras.append((camera_name, temp_camera))
            except SystemError:
                continue
        return valid_cameras

    def switch_camera(self, index: int):
        selected_camera = self.combo_cameras.currentData()

        if isinstance(self.current_camera, pygame.camera.Camera):
            try:
                self.current_camera.stop()
            except:
                pass

        self.current_camera = selected_camera

        if isinstance(self.current_camera, pygame.camera.Camera):
            self.current_camera.start()
            time.sleep(0.1)  # Add a short delay
        else:
            # The logic of capture is in update_frame
            pass

    def _numpy_to_surface(self, numpy_image: np.ndarray) -> pygame.Surface:
        # Convert numpy image (RGB) to pygame surface
        return pygame.surfarray.make_surface(numpy_image.transpose((1, 0, 2)))

    def _on_draw_surface(self, surface, barcode: BarcodeData):
        x, y, w, h = barcode.rect
        pygame.draw.rect(surface, (0, 255, 0), (x, y, w, h), 2)

    def get_barcodes(self, array: np.ndarray) -> List[BarcodeData]:
        if self.pyzbar:
            decoded_codes = self.pyzbar.decode(array)
            return [BarcodeData(data=decoded.data, rect=decoded.rect) for decoded in decoded_codes]
        elif self.cv2:
            array = self.cv2.transpose(array)
            array = self.cv2.cvtColor(array, self.cv2.COLOR_RGB2BGR)
            # Use OpenCV's QRCodeDetector to detect and decode the QR code.
            detector = self.cv2.QRCodeDetector()
            val, points, straight_qrcode = detector.detectAndDecode(array)

            barcodes = []
            if val:
                # If a QR code is detected, 'val' contains the decoded text.
                # 'points' contain the coordinates of the QR code corners.
                if points is not None:
                    # Convert points to a more manageable format
                    points = points[0]  # Points are returned in a nested array.

                    # Calculate the bounding rectangle using the points.
                    y, x, w, h = self.cv2.boundingRect(points.astype(np.int32))
                    rect = (x, y, w, h)  # Store the rectangle as a tuple

                    barcode = BarcodeData(val.encode(), rect)
                    barcodes.append(barcode)

            return barcodes
        else:
            return []

    def update_frame(self):

        barcodes = []
        if isinstance(self.current_camera, MSSBase):
            with mss.mss() as sct:
                monitor = sct.monitors[1]  # capture the first monitor
                sct_img = sct.grab(monitor)
                image = np.array(sct_img)

                # Convert BGRA to RGB by reordering the channels
                image = image[:, :, [2, 1, 0]]  # Rearrange BGR to RGB

                # Convert numpy image to surface for drawing
                surface = self._numpy_to_surface(image)
                surface = pygame.transform.flip(surface, True, False)
        elif isinstance(self.current_camera, pygame.camera.Camera):
            try:
                surface = self.current_camera.get_image()
            except:
                # print("Could not get image")
                return
        else:
            return

        barcodes = self.get_barcodes(pygame.surfarray.array3d(surface))
        surface = pygame.transform.flip(surface, False, True)
        surface = pygame.transform.rotate(surface, -90)

        for barcode in barcodes:
            self._on_draw_surface(surface, barcode)
            # only show the 1. barcode
            break

        surface = pygame.transform.flip(surface, False, True)
        self.showSurface(surface, scale_to=(640, 480))

        for barcode in barcodes:
            self.signal_raw_qr_data.emit(barcode.data)
            break

    def showSurface(self, surface: pygame.Surface, scale_to=(640, 480)):

        array3d = pygame.surfarray.array3d(surface)
        height, width, _ = array3d.shape
        bytes_per_line = 3 * width
        q_image = QtGui.QImage(array3d.data, width, height, bytes_per_line, QtGui.QImage.Format.Format_RGB888)

        # Convert QImage to QPixmap
        pixmap = QtGui.QPixmap.fromImage(q_image)

        # Scale the pixmap if scaling dimensions are provided
        if scale_to:
            pixmap = pixmap.scaled(
                scale_to[0],
                scale_to[1],
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            )

        self.label_image.setPixmap(pixmap)


class DemoVideoWidget(VideoWidget):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)  # type: ignore

        self.signal_raw_qr_data.connect(self.show_qr)

    def show_qr(self, qr_data):
        s = qr_data.decode("utf-8")
        print(s)
        self.label_qr.setText(s)
