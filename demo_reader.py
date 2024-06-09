import logging

from bitcoin_qr_tools.bitcoin_video_widget import DemoBitcoinVideoWidget

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)


from PyQt6 import QtWidgets

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)

    video_widget = DemoBitcoinVideoWidget()
    video_widget.show()

    sys.exit(app.exec())
