import logging

logger = logging.getLogger(__name__)


import time
from typing import List

import mss
import numpy as np
import pygame
import pygame.camera
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QEvent, pyqtSignal


class BarcodeData:
    def __init__(self, data, rect):
        self.data = data  # The decoded text of the barcode
        self.rect = rect  # The bounding rectangle of the barcode as a tuple (x, y, width, height)

    def __repr__(self):
        return f"BarcodeData(data={self.data}, rect={self.rect})"


class VideoWidget(QtWidgets.QWidget):
    signal_qr_data_callback = pyqtSignal(object)

    def __init__(self, qr_data_callback=None, parent=None):
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

        self.is_screen_capture = False
        self.screen_capturer = mss.mss()

        self.label_image = QtWidgets.QLabel()
        self.qr_data_callback = qr_data_callback
        self.signal_qr_data_callback.connect(qr_data_callback)

        pygame.camera.init()
        self.cameras = self.get_valid_cameras()
        self.combo_cameras = QtWidgets.QComboBox()
        self.combo_cameras.addItems(self.cameras)
        self.combo_cameras.currentIndexChanged.connect(self.switch_camera)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.label_image)
        layout.addWidget(self.combo_cameras)

        self.setLayout(layout)

        self.capture = None

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_frame)
        self.timer.start(int(1000.0 / 30.0))  # 30 FPS

        # Add "Screen" option for screen capture
        self.combo_cameras.addItem("Screen")
        self.cameras.append("Screen")  # Adding "Screen" to the cameras list
        self.switch_camera(0)

    def closeEvent(self, event: QEvent) -> None:
        self.timer.stop()
        if self.capture:
            try:
                self.capture.stop()
            except:
                pass

        # If you call the parent's closeEvent(), it will proceed to close the widget
        super().closeEvent(event)

    def get_valid_cameras(self):
        valid_cameras = []
        for camera in pygame.camera.list_cameras():
            try:
                temp_camera = pygame.camera.Camera(camera, (640, 480))
                temp_camera.start()
                temp_camera.stop()
                valid_cameras.append(camera)
            except SystemError:
                continue
        return valid_cameras

    def switch_camera(self, index: int):
        selected_camera = self.combo_cameras.currentText()
        if selected_camera == "Screen":
            self.is_screen_capture = True
            # Additional logic for initializing screen capture can be added here
        else:
            self.is_screen_capture = False

            if self.capture:
                try:
                    self.capture.stop()
                except:
                    pass

            self.capture = pygame.camera.Camera(self.cameras[index], (640, 480))
            self.capture.start()
            time.sleep(0.1)  # Add a short delay

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
        if self.is_screen_capture:
            with mss.mss() as sct:
                monitor = sct.monitors[1]  # capture the first monitor
                sct_img = sct.grab(monitor)
                image = np.array(sct_img)

                # Convert BGRA to RGB
                image = image[:, :, :3]

                # Convert numpy image to surface for drawing
                surface = self._numpy_to_surface(image)
        else:
            try:
                surface = self.capture.get_image()
            except:
                # print("Could not get image")
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
            self.signal_qr_data_callback.emit(barcode.data)
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
        super().__init__(qr_data_callback=self.show_qr, parent=parent)

        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)

    def show_qr(self, qr_data):
        s = qr_data.decode("utf-8")
        print(s)
        self.label_qr.setText(s)
