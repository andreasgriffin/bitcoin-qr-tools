from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

from bitcoin_qrreader.bitcoin_qr_gui import DemoBitcoinVideoWidget
import sys


def main():

    app = QApplication(sys.argv)
    window = DemoBitcoinVideoWidget()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
