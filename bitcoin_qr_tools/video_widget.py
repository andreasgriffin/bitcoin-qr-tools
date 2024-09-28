import logging

from bitcoin_qr_tools.rtsp_camera import RTSPCamera

logger = logging.getLogger(__name__)

import time
from typing import List, Tuple, Union

import mss
import numpy as np
import pygame
import pygame.camera
from mss.base import MSSBase
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QSizePolicy,
    QSlider,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .cv2camera import CV2Camera


class BarcodeData:
    def __init__(self, data, rect):
        self.data = data  # The decoded text of the barcode
        self.rect = rect  # The bounding rectangle of the barcode as a tuple (x, y, width, height)

    def __repr__(self):
        return f"BarcodeData(data={self.data}, rect={self.rect})"


TypeSomeCamera = Union[CV2Camera, RTSPCamera, pygame.camera.Camera]


class VideoWidget(QWidget):
    signal_raw_qr_data = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Camera"))
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

        self.label_image = QLabel()
        self.lower_widget = QWidget()
        self.lower_widget_layout = QHBoxLayout(self.lower_widget)

        self.combo_cameras = QComboBox()
        self.combo_cameras.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.label_camera_choose = QLabel(self.tr("Camera:"))
        self.lower_widget_layout.addWidget(self.label_camera_choose)
        self.lower_widget_layout.addWidget(self.combo_cameras)

        # Create the tool button
        settingsButton = QToolButton(self)
        settingsButton.setText(self.tr("Settings"))
        settingsButton.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )  # Show text beside the icon
        self.lower_widget_layout.addWidget(settingsButton)

        # Create a menu for the button
        menu = QMenu("", self)

        # Add actions to the menu
        action_add_rtsp_camera = QAction("Add RTSP Camera", self)
        menu.addAction(action_add_rtsp_camera)
        action_add_rtsp_camera.triggered.connect(self.prompt_rtsp_url)

        # Set the menu to the tool button
        settingsButton.setMenu(menu)
        settingsButton.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

        self.middle_widget = QWidget()
        self.middle_widget_layout = QHBoxLayout(self.middle_widget)

        # Create slider
        self.slider = QSlider(Qt.Orientation.Horizontal, self)
        self.slider.setMinimum(10)
        self.slider.setMaximum(50)
        self.slider.setValue(10)  # Default value
        self.slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.slider.setTickInterval(1)

        self.label_slider = QLabel(self.tr("Zoom:"))
        self.middle_widget_layout.addWidget(self.label_slider)
        self.middle_widget_layout.addWidget(self.slider)

        pygame.camera.init()
        for camera_name, camera in self.get_valid_cameras():
            self.combo_cameras.addItem(str(camera_name), userData=camera)

        layout = QVBoxLayout()
        layout.addWidget(self.label_image)
        layout.addWidget(self.middle_widget)
        layout.addWidget(self.lower_widget)

        self.setLayout(layout)

        self.current_camera: TypeSomeCamera | None = None

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

    @property
    def zoom(self) -> float:
        return self.slider.value() / 10

    def prompt_rtsp_url(self):
        text, ok = QInputDialog.getText(self, "Enter RTSP URL", "RTSP URL:")
        if ok and text:
            self.add_rtsp_camera(text)

    def add_rtsp_camera(self, url: str):
        # Here you would add your actual logic to handle the RTSP camera
        # This is a placeholder function to illustrate what you might do
        print("Adding RTSP Camera with URL:", url)
        # Assume validation of the URL or further actions here

        for enable_udp in [False, True]:
            temp_camera = RTSPCamera(url)
            try:
                temp_camera.start(enable_udp=enable_udp)
                temp_camera.stop()
                self.combo_cameras.addItem(str(url), userData=temp_camera)
                self.combo_cameras.setCurrentIndex(self.combo_cameras.count() - 1)
                self.switch_camera(self.combo_cameras.count() - 1)
                return
            except:
                logger.debug(f"{temp_camera} with enable_udp {enable_udp} could not be opened")

        QMessageBox().warning(None, "Error", "The camera could not be opened")

    def closeEvent(self, event: QtGui.QCloseEvent | None) -> None:
        self.timer.stop()
        if self.current_camera:
            try:
                self.current_camera.stop()
            except:
                pass

        # If you call the parent's closeEvent(), it will proceed to close the widget
        super().closeEvent(event)

    @staticmethod
    def get_pygame_camera(camera_name: str | int) -> pygame.camera.Camera | None:
        try:
            temp_camera = pygame.camera.Camera(camera_name, (640, 480))
            temp_camera.start()
            temp_camera.stop()
            logger.debug(f"Found pygame.camera.Camera({camera_name}, (640, 480))")
            return temp_camera
        except Exception as e:
            logger.debug(f"Could not get  pygame.camera.Camera({camera_name}, (640, 480)). {e} ")
        return None

    @staticmethod
    def get_cv2camera(index: int) -> CV2Camera | None:
        try:
            temp_camera = CV2Camera(index, (640, 480))
            temp_camera.start()
            temp_camera.stop()
            logger.debug(f"Found CV2Camera({index}, (640, 480))")
            return temp_camera
        except Exception as e:
            logger.debug(f"Could not get  CV2Camera({index}, (640, 480)). {e} ")

        return None

    def get_valid_cameras(self) -> List[Tuple[str, TypeSomeCamera]]:
        valid_cameras: List[Tuple[str, TypeSomeCamera]] = []
        for index, camera_name in enumerate(pygame.camera.list_cameras()):
            temp_camera = self.get_pygame_camera(camera_name) or self.get_cv2camera(index)
            if temp_camera:
                valid_cameras.append((camera_name, temp_camera))

        if not valid_cameras:
            temp_camera = self.get_pygame_camera(0) or self.get_cv2camera(0)
            if temp_camera:
                valid_cameras.append((str(0), temp_camera))

        return valid_cameras

    def switch_camera(self, index: int):
        selected_camera = self.combo_cameras.currentData()

        if isinstance(self.current_camera, (CV2Camera, RTSPCamera, pygame.camera.Camera)):
            try:
                self.current_camera.stop()
            except:
                pass

        self.current_camera = selected_camera

        if isinstance(self.current_camera, (CV2Camera, RTSPCamera, pygame.camera.Camera)):
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

    @staticmethod
    def crop(
        image_surface: pygame.Surface, left: float, right: float, top: float, bottom: float
    ) -> pygame.Surface:
        """
        Crop the image based on the specified proportions from each edge using Pygame.

        :param image_surface: The full image as a pygame.Surface.
        :param left: Proportion of the width to crop from the left.
        :param right: Proportion of the width to crop from the right.
        :param top: Proportion of the height to crop from the top.
        :param bottom: Proportion of the height to crop from the bottom.
        :return: Cropped image as a pygame.Surface.
        """
        w, h = image_surface.get_size()
        left_idx = int(w * left)
        right_idx = int(w * (1 - right))
        top_idx = int(h * top)
        bottom_idx = int(h * (1 - bottom))

        # Ensure the indices are within the image dimensions
        left_idx = max(left_idx, 0)
        right_idx = min(right_idx, w)
        top_idx = max(top_idx, 0)
        bottom_idx = min(bottom_idx, h)

        # Define the rectangle for the subsurface
        rect = pygame.Rect(left_idx, top_idx, right_idx - left_idx, bottom_idx - top_idx)

        # Return the subsurface
        return image_surface.subsurface(rect)

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
        elif isinstance(self.current_camera, (CV2Camera, RTSPCamera, pygame.camera.Camera)):
            try:
                surface = self.current_camera.get_image()
            except:
                # print("Could not get image")
                return
        else:
            return

        crop_value = min((1 - 1 / self.zoom) / 2, 0.48)
        surface = self.crop(
            surface,
            crop_value,
            crop_value,
            crop_value,
            crop_value,
        )
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
