import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
from bitcoin_qrreader.qr_qui import DemoVideoWidget

logger = logging.getLogger(__name__)


from PyQt6 import QtWidgets

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)

    video_widget = DemoVideoWidget()
    video_widget.show()

    sys.exit(app.exec())
