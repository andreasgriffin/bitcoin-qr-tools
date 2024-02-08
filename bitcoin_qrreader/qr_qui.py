import pygame
import pygame.camera
from PyQt6 import QtCore, QtWidgets, QtGui
from pyzbar import pyzbar
import time
from PyQt6.QtCore import QEvent
import mss
import numpy as np
from PyQt6.QtCore import pyqtSignal


class VideoWidget(QtWidgets.QWidget):
    signal_qr_data_callback = pyqtSignal(object)

    def __init__(self, qr_data_callback=None, parent=None):
        super().__init__(parent)
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

    def switch_camera(self, index):
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

    def _numpy_to_surface(self, numpy_image):
        # Convert numpy image (RGB) to pygame surface
        return pygame.surfarray.make_surface(numpy_image.transpose((1, 0, 2)))

    def _surface_to_numpy(self, surface):
        # Convert pygame surface to numpy array (RGB)
        return pygame.surfarray.array3d(surface).transpose((1, 0, 2))

    def _on_draw_surface(self, surface, barcode):
        x, y, w, h = barcode.rect
        pygame.draw.rect(surface, (0, 255, 0), (x, y, w, h), 2)

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

        barcodes = pyzbar.decode(pygame.surfarray.array3d(surface))
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

    def showSurface(self, surface, scale_to=(640, 480)):

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


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)

    video_widget = DemoVideoWidget()
    video_widget.show()

    sys.exit(app.exec_())
