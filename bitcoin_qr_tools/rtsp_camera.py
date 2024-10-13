import logging
import os
import sys

import cv2
import pygame
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QImage, QPixmap
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget

logger = logging.getLogger(__name__)


class RTSPCamera:
    def __init__(self, rtsp_url: str):
        """
        Initialize the RTSP camera with the given URL and resolution.

        :param rtsp_url: str, the RTSP URL to the camera stream
        :param resolution: tuple, the resolution of the camera as (width, height)
        """
        self.rtsp_url = rtsp_url
        self._cam: cv2.VideoCapture | None = None
        self._open = False

    def start(self, enable_udp=False):
        """
        Start the RTSP camera capture.
        """

        if enable_udp:
            os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;udp"

        self._cam = cv2.VideoCapture(self.rtsp_url)

        self.width = int(self._cam.get(cv2.CAP_PROP_FRAME_WIDTH))
        self.height = int(self._cam.get(cv2.CAP_PROP_FRAME_HEIGHT))
        self.fps = self._cam.get(cv2.CAP_PROP_FPS)  # Reading the frames per second

        logger.debug(f"Stream resolution: {self.width}x{self.height}, FPS: {self.fps}")

        if not self._cam.isOpened():
            raise ValueError("Could not open camera stream.")

        self._open = True

    def stop(self):
        """
        Stop the RTSP camera capture.
        """
        if self._open and self._cam:
            self._cam.release()
            self._open = False

    def get_image(self):
        """
        Capture a single frame from the RTSP stream.

        :return: The captured frame as a numpy array, or None if capture failed.
        """
        if not self._open or not self._cam:
            raise RuntimeError("Camera is not initialized, call start() first")

        ret, frame = self._cam.read()
        if not ret:
            raise RuntimeError("Failed to capture image")

        # Convert numpy array to pygame.Surface
        surface = pygame.surfarray.make_surface(frame.swapaxes(0, 1))
        surface = pygame.transform.flip(surface, True, False)
        return surface

    def __del__(self):
        """
        Ensure the camera stream is released when the object is destroyed.
        """
        self.stop()


if __name__ == "__main__":

    class MainWindow(QWidget):
        def __init__(self, rtsp_url):
            super().__init__()
            self.camera = RTSPCamera(rtsp_url)
            self.camera.start(enable_udp=True)

            self.label_image = QLabel(self)
            self._layout = QVBoxLayout(self)
            self._layout.addWidget(self.label_image)
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.update_frame)
            self.timer.start(30)  # Update at ~33fps

        def showSurface(self, surface: pygame.Surface, scale_to=(640, 480)):
            array3d = pygame.surfarray.array3d(surface)
            height, width, _ = array3d.shape
            bytes_per_line = 3 * width
            q_image = QImage(array3d.data, width, height, bytes_per_line, QImage.Format.Format_RGB888)

            # Convert QImage to QPixmap
            pixmap = QPixmap.fromImage(q_image)

            # Scale the pixmap if scaling dimensions are provided
            if scale_to:
                pixmap = pixmap.scaled(
                    scale_to[0],
                    scale_to[1],
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )

            self.label_image.setPixmap(pixmap)

        def update_frame(self):
            frame = self.camera.get_image()

            self.showSurface(frame)
            # image = QImage(frame.data, frame.shape[1], frame.shape[0], QImage.Format.Format_RGB888)
            # pixmap = QPixmap.fromImage(image)
            # self.label_image.setPixmap(pixmap)

        def closeEvent(self, event):
            self.timer.stop()
            self.camera.stop()
            super().closeEvent(event)

    app = QApplication(sys.argv)
    window = MainWindow("rtsp://192.168.178.27:8086/webcam")
    window.show()
    sys.exit(app.exec())
