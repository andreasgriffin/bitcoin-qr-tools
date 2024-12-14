#
# Bitcoin Safe
# Copyright (C) 2024 Andreas Griffin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see https://www.gnu.org/licenses/gpl-3.0.html
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from PIL import Image
from PyQt6.QtCore import QByteArray, QEvent, QObject, QRectF, QSize, Qt, QTimer
from PyQt6.QtGui import (
    QCloseEvent,
    QEnterEvent,
    QIcon,
    QImage,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPixmap,
)
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from bitcoin_qr_tools.data import Data
from bitcoin_qr_tools.qr_generator import QRGenerator
from bitcoin_qr_tools.unified_encoder import QrExportTypes, UnifiedEncoder

logger = logging.getLogger(__name__)


def resource_path(*parts: str):
    pkg_dir = os.path.split(os.path.realpath(__file__))[0]
    return os.path.join(pkg_dir, *parts)


def icon_path(icon_basename: str):
    return resource_path("gui", "icons", icon_basename)


def pil_image_to_qimage(im: Image.Image):
    im = im.convert("RGBA")
    data = im.tobytes("raw", "RGBA")
    qim = QImage(data, im.size[0], im.size[1], QImage.Format.Format_RGBA8888)

    return qim.copy()  # Making a copy to let data persist after function returns


class ImageWidget(QWidget):
    def __init__(
        self, pil_image: Image.Image | None = None, parent=None, size_hint: Tuple[int, int] | None = None
    ):
        super().__init__(parent)
        self.pil_image = pil_image
        self.size_hint = size_hint
        self.qt_image = pil_image_to_qimage(pil_image) if pil_image else QImage()
        self.scaled_image = self.qt_image

    def paintEvent(self, event: QPaintEvent | None) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

        if not self.qt_image.isNull():
            widget_width, widget_height = self.width(), self.height()

            # choose minimum of image and self sizes
            width = min(self.qt_image.size().width(), widget_width)
            height = min(self.qt_image.size().height(), widget_height)

            # Scale the image to fit within the widget while maintaining aspect ratio
            self.scaled_image = self.qt_image.scaled(
                width, height, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )

            # Calculate position to center the image
            x = (widget_width - self.scaled_image.width()) // 2
            y = (widget_height - self.scaled_image.height()) // 2

            # Draw the image centered
            painter.drawImage(x, y, self.scaled_image)

    def set_image(self, pil_image: Image.Image):
        self.pil_image = pil_image
        self.qt_image = pil_image_to_qimage(pil_image)
        self.update()  # Trigger a repaint

    def load_from_file(self, filepath: str):
        self.set_image(Image.open(filepath))

    def sizeHint(self) -> QSize:
        if not self.qt_image.isNull():
            if not self.size_hint:
                return self.qt_image.size()
            else:
                s = QSize()
                s.setWidth(self.size_hint[0])
                s.setHeight(self.size_hint[1])
                return s
        return super().sizeHint()


class EnlargableImageWidget(ImageWidget):
    def __init__(
        self, pil_image: Image.Image | None = None, parent=None, size_hint: Tuple[int, int] | None = None
    ):
        super().__init__(pil_image, parent, size_hint=size_hint)
        self.enlarged_image: Optional[EnlargedImage] = None
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def enlarge_image(self):
        if not self.enlarged_image:
            self.enlarged_image = EnlargedImage(self.pil_image)

        if self.enlarged_image.isVisible():
            self.enlarged_image.close()
        else:
            self.enlarged_image.show()

    def mousePressEvent(self, event: QMouseEvent | None):
        self.enlarge_image()
        super().mousePressEvent(event)

    def closeEvent(self, event: QCloseEvent | None) -> None:
        if self.enlarged_image:
            self.enlarged_image.close()
        super().closeEvent(event)


class EnlargedImage(ImageWidget):
    def __init__(self, pil_image: Image.Image, parent=None, screen_fraction=0.7):
        super().__init__(pil_image, parent)
        self.setWindowTitle("Enlarged Image")
        self.installEventFilter(self)  # Install the event filter for this widget

        # Get screen resolution
        screen = QApplication.screens()[0].size()

        # Calculate the new size maintaining the aspect ratio
        image_aspect_ratio = self.qt_image.width() / self.qt_image.height()
        new_width = min(screen.width() * screen_fraction, self.qt_image.width())
        new_height = new_width / image_aspect_ratio

        # Ensure the height does not exceed 50% of the screen height
        if new_height > screen.height() * screen_fraction:
            new_height = screen.height() * screen_fraction
            new_width = new_height * image_aspect_ratio

        # Calculate position to center the window
        x = round((screen.width() - new_width) / 2)
        y = round((screen.height() - new_height) / 2)

        self.setGeometry(x, y, round(new_width), round(new_height))

    def eventFilter(self, source: QObject | None, event: QEvent | None) -> bool:
        # Check for the FocusOut event
        if event and event.type() in [QEvent.Type.FocusOut, QEvent.Type.WindowDeactivate]:
            # Close the widget if it loses focus
            if source is self:
                self.close()
        return super().eventFilter(source, event)

    def mousePressEvent(self, event: QMouseEvent | None):
        self.close()

    def keyPressEvent(self, event: QKeyEvent | None):
        if event and event.key() == Qt.Key.Key_Escape:
            self.close()


class EnlargableImageWidgetWithButton(QWidget):
    def __init__(
        self,
        pil_image: Image.Image | None = None,
        parent: QWidget | None = None,
        size_hint: Tuple[int, int] | None = None,
    ):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        self.enlargable_widget = EnlargableImageWidget(pil_image=pil_image, parent=self, size_hint=size_hint)

        layout.addWidget(self.enlargable_widget)

        self.button_enlarge_qr = QPushButton()
        self.button_enlarge_qr.setIcon(QIcon(icon_path("zoom.png")))
        # self.button_enlarge_qr.setIconSize(QSize(30, 30))  # 24x24 pixels
        self.button_enlarge_qr.clicked.connect(self.enlargable_widget.enlarge_image)
        self.button_enlarge_qr.setText(self.tr("Enlarge"))
        self.button_enlarge_qr.setMaximumWidth(200)
        layout.addWidget(self.button_enlarge_qr, alignment=Qt.AlignmentFlag.AlignHCenter)

    def load_from_file(self, filepath: str):
        self.enlargable_widget.load_from_file(filepath=filepath)


class QRCodeWidget(EnlargableImageWidget):
    def __init__(self, parent=None, clickable=True):
        super().__init__(parent=parent)
        # QR code specific initializations, if any

    def set_data(self, data: str):
        # Implement QR code generation and setting image
        self.set_image(QRGenerator.create_qr_PILimage(data))


#######################################
# svg widgets


class QRCodeWidgetSVG(QWidget):
    def __init__(self, always_animate=False, clickable=True, parent=None):
        super().__init__(parent)
        self.svg_renderers: List[QSvgRenderer] = []
        self.current_index = 0
        self.enlarged_image = None
        self.clickable = clickable
        self.always_animate = always_animate
        self.is_hovered = False
        self.default_size = 200
        self.setBaseSize(self.default_size, self.default_size)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumSize(20, 20)

        if clickable:
            self.setCursor(Qt.CursorShape.PointingHandCursor)

        self.timer = QTimer()
        self.timer.timeout.connect(self.next_svg)

    def set_renderers(self, svg_renderers):
        self.svg_renderers = svg_renderers
        self.current_index = 0
        if self.enlarged_image:
            if self.svg_renderers:
                self.enlarged_image.update_image(self.svg_renderers[self.current_index])
            else:
                self.enlarged_image.update_image(None)
        self.manage_animation()
        # if i update, when it is not visible, then I force the window to show
        if self.isVisible():
            self.update()

    def set_data_list(self, data_list: List[str]):
        self.set_renderers(
            [QSvgRenderer(QByteArray(QRGenerator.create_qr_svg(data).encode("utf-8"))) for data in data_list]
        )

    def set_always_animate(self, always_animate: bool):
        self.always_animate = always_animate
        self.manage_animation()

    def set_images(self, image_list: List[str]):
        self.set_renderers([QSvgRenderer(QByteArray(image.encode("utf-8"))) for image in image_list])

    def manage_animation(self):
        should_animate = len(self.svg_renderers) > 1 and (
            self.always_animate
            or self.is_hovered
            or (self.enlarged_image and self.enlarged_image.isVisible())
        )
        if should_animate:
            self.timer.start(1000)  # Change SVG every 1 second
        else:
            self.timer.stop()

    def next_svg(self):
        if not self.svg_renderers:
            return

        self.current_index = (self.current_index + 1) % len(self.svg_renderers)
        self.update()
        if self.enlarged_image and self.enlarged_image.isVisible():
            self.enlarged_image.update_image(self.svg_renderers[self.current_index])
        else:
            self.manage_animation()

    def paintEvent(self, event: QPaintEvent | None) -> None:
        if not self.svg_renderers:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        widget_width, widget_height = self.width(), self.height()
        side = min(widget_width, widget_height)
        x = (widget_width - side) // 2
        y = (widget_height - side) // 2

        self.svg_renderers[self.current_index].render(painter, QRectF(x, y, side, side))

    def enterEvent(self, event: QEnterEvent | None) -> None:
        self.is_hovered = True
        self.manage_animation()
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent | None) -> None:
        self.is_hovered = False
        self.manage_animation()
        super().leaveEvent(event)

    def enlarge_image(self):
        if not self.svg_renderers:
            return

        if not self.enlarged_image:
            self.is_hovered = False
            self.enlarged_image = EnlargedSVG(self.svg_renderers[self.current_index])

        self.enlarged_image.exec()
        self.enlarged_image.update_image(self.svg_renderers[self.current_index])
        self.manage_animation()

    def mousePressEvent(self, event: QMouseEvent | None):
        if self.clickable:
            self.enlarge_image()
        super().mousePressEvent(event)

    def save_file(self, filename: Path, antialias=False):
        """Save all QR codes to files. If format is 'GIF', combines them into
        an animated GIF.

        :param filename:
        :param antialias: Boolean to indicate if anti-aliasing should be
            used.
        """
        if len(self.svg_renderers) > 1:
            images: List[Image.Image] = []
            for renderer in self.svg_renderers:
                if not renderer.isValid():
                    continue
                images.append(self.renderer_to_pil(renderer, antialias))
            images[0].save(
                str(filename),
                format="gif",
                save_all=True,
                append_images=images[1:],
                loop=0,
                duration=1000,
            )
        elif len(self.svg_renderers) == 1:
            renderer = self.svg_renderers[0]
            if renderer.isValid():
                image = self.renderer_to_pil(renderer, antialias)
                image.save(str(filename))

    def renderer_to_pil(self, renderer: QSvgRenderer, antialias: bool) -> Image.Image:
        """Convert a QR code renderer to a PIL Image.

        :param renderer: The QR code renderer.
        :param antialias: Boolean to indicate if anti-aliasing should be
            used.
        :return: PIL Image object.
        """
        # setting the length that it can handle the largets qr codes:
        # Version 40: 177x177 modules
        length = 177 * 2

        pixmap = QPixmap(length, length)
        pixmap.fill(Qt.GlobalColor.white)
        painter = QPainter(pixmap)

        if antialias:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        renderer.render(painter, QRectF(0, 0, length, length))
        painter.end()

        # Convert QPixmap to QImage
        qimage = pixmap.toImage()

        return self.qimage_to_pil(qimage=qimage)

    @staticmethod
    def qimage_to_pil(qimage: QImage) -> Image.Image:
        """Convert QImage to PIL Image."""
        qimage = qimage.convertToFormat(QImage.Format.Format_RGB32)

        width = qimage.width()
        height = qimage.height()

        # Get the data from the QImage
        # 4 bytes per pixel
        buffer = qimage.bits().asstring(width * height * 4)  # type: ignore

        # Create a PIL Image from the buffer
        pil_image = Image.frombytes("RGBA", (width, height), buffer, "raw", "BGRA")

        return pil_image

    def as_pil_images(self):
        """Convert all the QR codes to PIL Images.

        :return: List of PIL Image objects.
        """
        return [
            self.renderer_to_pil(renderer, antialias=True)
            for renderer in self.svg_renderers
            if renderer.isValid()
        ]

    def closeEvent(self, event: QCloseEvent | None) -> None:
        self.timer.stop()
        if self.enlarged_image:
            self.enlarged_image.close()
        super().closeEvent(event)


class EnlargedSVG(QDialog):
    def __init__(self, svg_renderer: QSvgRenderer, parent=None, screen_fraction=0.5):
        super().__init__(parent)
        self.svg_renderer = svg_renderer
        self.setWindowTitle("QR Code")
        # self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        screen = QApplication.screens()[0].size()
        width = height = round(min(screen.width(), screen.height()) * screen_fraction)
        self.setGeometry(
            round((screen.width() - width) / 2),
            round((screen.height() - height) / 2),
            width,
            height,
        )

    def update_image(self, new_renderer: QSvgRenderer):
        self.svg_renderer = new_renderer
        self.update()

    def paintEvent(self, event: QPaintEvent | None) -> None:
        if not self.svg_renderer:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        widget_width, widget_height = self.width(), self.height()
        side = min(widget_width, widget_height)
        x = (widget_width - side) // 2
        y = (widget_height - side) // 2

        self.svg_renderer.render(painter, QRectF(x, y, side, side))

    def mousePressEvent(self, event: QMouseEvent | None):
        super().mousePressEvent(event)
        self.close()

    def keyPressEvent(self, event: QKeyEvent | None):
        if event and event.key() == Qt.Key.Key_Escape:
            self.close()


if __name__ == "__main__":
    import bdkpython as bdk

    testdata = [
        Data.from_str(
            "cHNidP8BAHEBAAAAAXgQzjk+DTWQTPUtRMbYiheC0jfbipvw+jQ5lidmyABjAAAAAAD9////AgDh9QUAAAAAFgAUbBuOQOlcnz8vpruh2Kb3CFr4vlhkEQ2PAAAAABYAFN1n2hvBWYzshD42xwQzy9XYoji3BAEAAAABAKoCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BQKYAAEB/////wIA+QKVAAAAABYAFLlHwN6VXNLM381bMxmNJlaDTQzVAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkBIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBHwD5ApUAAAAAFgAUuUfA3pVc0szfzVszGY0mVoNNDNUiBgISCnRxeOxzC0MgK01AmiIRLrgS1AyIqKeBkdwL+nt/6RikLG3TVAAAgAEAAIAAAACAAAAAAAAAAAAAACICAlQcwExiTUk9f7olLkwPlQpiregRHc9jXXFJBlMoucgNGKQsbdNUAACAAQAAgAAAAIAAAAAAAQAAAAA=",
            network=bdk.Network.REGTEST,
        ),
        Data.from_str(
            "wsh(sortedmulti(2,[829074ff/48'/1'/0'/2']tpubDDx9arPwEvHGnnkKN1YJXFE4W6JZXyVX9HGjZW75nWe1FCsTYu2k3i7VtCwhGR9zj6UUYnseZUnwL7T6Znru3NmXkcjEQxMqRx7Rxz8rPp4/<0;1>/*,[45f35351/48'/1'/0'/2']tpubDEY3tNWvDs8J6xAmwoirxgff61gPN1V6U5numeb6xjvZRB883NPPpRYHt2A6fUE3YyzDLezFfuosBdXsdXJhJUcpqYWF9EEBmWqG3rG8sdy/<0;1>/*,[d5b43540/48'/1'/0'/2']tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF/<0;1>/*))#2jxldwxn",
            network=bdk.Network.REGTEST,
        ),
        Data.from_str(
            "wpkh([a42c6dd3/84h/1h/0h]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)",
            network=bdk.Network.REGTEST,
        ),
        Data.from_str(
            "0100000000010177ff6b4de45caf689a95367958ff6b912c2385d4d7563a09ba41cb0a2c30f5220000000000fdffffff02a0cee90100000000160014f22e4b1c92222a38b286fdd39ee2e35d4b581c47d62019930000000016001412c9e0c94dd6c71cfec7bcff16feea0a0fb8bc5d0247304402205c88d4d7e3059f16c6f74debb9754efeba89f92a237b7d09d9732e59b8a7d6de02202ce0ef338af77ebd8c14ae88f7e83116e0ba27a89aee7829ef70d1fc8d99af06012102802e1fda05b62b1f071d35bcd129fc0f9cf3517c6af7b3bb0ce76d76c7de068d00000000",
            network=bdk.Network.REGTEST,
        ),
        Data.from_str(
            "[a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*",
            network=bdk.Network.REGTEST,
        ),
        Data.from_str(
            '{"chain": "XRT", "xfp": "0F056943", "p2sh": {"xpub": "tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n", "deriv": "m/45h", "first": null, "name": "p2sh"}, "p2sh_p2wsh": {"xpub": "tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP", "deriv": "m/48h/1h/0h/1h", "first": null, "name": "p2sh_p2wsh"}, "p2wsh": {"xpub": "tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP", "deriv": "m/48h/1h/0h/2h", "first": null, "name": "p2wsh"}}',
            network=bdk.Network.REGTEST,
        ),
    ]

    class ComboBoxDemo(QWidget):
        def __init__(self):
            super().__init__()

            # Setup the layout
            layout = QVBoxLayout()

            # enlarable_widget2 = EnlargableImageWidgetWithButton()
            # enlarable_widget2.load_from_file("docs/bad-light.png")
            # layout.addWidget(enlarable_widget2)

            self.svg_widget = QRCodeWidgetSVG()
            self.svg_widget.set_always_animate(True)
            layout.addWidget(self.svg_widget)

            # Initialize combo box 1
            self.combo_data = QComboBox()
            for data in testdata:
                self.combo_data.addItem(data.data_type.name, data)
            self.combo_data.currentIndexChanged.connect(self.on_combo_changed)
            layout.addWidget(self.combo_data)

            # Initialize combo box 2
            self.combo_qrtype = QComboBox()
            for qr_type in QrExportTypes.as_list():
                self.combo_qrtype.addItem(qr_type.display_name, qr_type)
            self.combo_qrtype.currentIndexChanged.connect(self.on_combo_changed)
            layout.addWidget(self.combo_qrtype)

            # Set the layout to the QWidget
            self.setLayout(layout)

            self.on_combo_changed()

        def on_combo_changed(self):
            # Get current data from both combo boxes
            data = self.combo_data.currentData()
            qrtype = self.combo_qrtype.currentData()

            fragments = UnifiedEncoder.generate_fragments_for_qr(data=data, qr_export_type=qrtype)
            self.svg_widget.set_data_list(fragments)

    app = QApplication(sys.argv)
    window = ComboBoxDemo()
    window.show()
    sys.exit(app.exec())
