import pygame
import pygame.camera
from PySide2 import QtCore, QtWidgets, QtGui
from pyzbar import pyzbar
import time
from PySide2.QtCore import QEvent


class VideoWidget(QtWidgets.QWidget):
    signal_qr_data_callback = QtCore.Signal(object)

    def __init__(self, qr_data_callback=None, parent=None):
        super().__init__(parent)

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
        self.switch_camera(0)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_frame)
        self.timer.start(1000.0 / 30.0)  # 30 FPS

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
        if self.capture:
            try:
                self.capture.stop()
            except:
                pass

        self.capture = pygame.camera.Camera(self.cameras[index], (640, 480))
        self.capture.start()
        time.sleep(0.1)  # Add a short delay

    def update_frame(self):
        try:
            surface = self.capture.get_image()
            surface = pygame.transform.rotate(surface, 90)
            barcodes = pyzbar.decode(pygame.surfarray.array3d(surface))

            for barcode in barcodes:
                x, y, w, h = barcode.rect
                y_new = x
                x_new = y
                rect = pygame.Rect(
                    x_new, y_new, h, w
                )  # swapped width and height as well
                pygame.draw.rect(surface, (0, 255, 0), rect, 2)
                # only show the 1. barcode
                break

            frame = pygame.surfarray.array3d(surface)

            self.show_image(frame)

            for barcode in barcodes:
                self.signal_qr_data_callback.emit(barcode.data)
                break
        except:
            # print("Could not get image")
            pass

    def show_image(self, image):
        height, width, _ = image.shape
        bytes_per_line = 3 * width
        q_image = QtGui.QImage(
            image.data, width, height, bytes_per_line, QtGui.QImage.Format_RGB888
        )
        self.label_image.setPixmap(QtGui.QPixmap.fromImage(q_image))


class DemoVideoWidget(VideoWidget):
    def __init__(self, parent=None):
        super().__init__(qr_data_callback=self.show_qr, parent=parent)

        self.label_qr = QtWidgets.QLabel()

        self.layout().addWidget(self.label_qr)

    def show_qr(self, qr_data):
        self.label_qr.setText(qr_data.decode("utf-8"))


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)

    video_widget = DemoVideoWidget()
    video_widget.show()

    sys.exit(app.exec_())
