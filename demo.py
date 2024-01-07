from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *

from bitcoin_qrreader.bitcoin_qr_gui import DemoBitcoinVideoWidget
import sys


def main():

    app = QApplication(sys.argv)
    window = DemoBitcoinVideoWidget()
    window.show()
    app.exec_()


if __name__ == "__main__":
    main()
