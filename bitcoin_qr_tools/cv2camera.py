import sys

import cv2
import pygame
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QImage, QPixmap
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget


class CV2Camera:
    def __init__(self, device_index=0, resolution=None, mode="RGB"):
        self.device_index = device_index
        self.resolution = resolution
        self._cam = None
        self._open = False
        self.mode = mode

    def start(self):
        self._cam = cv2.VideoCapture(self.device_index)

        if not self._cam.isOpened():
            raise ValueError("Could not open camera")
        self._open = True

    def stop(self):
        if self._open and self._cam:
            self._cam.release()
            self._open = False

    def get_image(self) -> pygame.Surface:
        if not self._open or not self._cam:
            raise ValueError("Camera must be started")
        ret, image = self._cam.read()
        if not ret:
            raise ValueError("Failed to capture image")
        if self.mode == "RGB":
            image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

        # Convert numpy array to pygame.Surface
        surface = pygame.surfarray.make_surface(image.swapaxes(0, 1))
        return surface

    def __del__(self):
        self.stop()


if __name__ == "__main__":

    class MainWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.camera = CV2Camera(device_index=0, resolution=(640, 480), mode="RGB")
            self.camera.start()

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
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
