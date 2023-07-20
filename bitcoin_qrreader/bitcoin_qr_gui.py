from .qr_qui import VideoWidget
from .bitcoin_qr import *
from PySide2 import QtWidgets


class BitcoinVideoWidget(VideoWidget):
    def __init__(
        self,
        result_callback=None,
        close_on_result=True,
        parent=None,
        network=bdk.Network.REGTEST,
    ):
        super().__init__(qr_data_callback=self.qr_data_callback, parent=parent)

        self.network = network
        self.data = None
        self.result_callback = result_callback
        self.close_on_result = close_on_result

    def qr_data_callback(self, qr_data):
        data = Data.from_str(qr_data.decode("utf-8"), network=self.network)

        if not data:
            return

        self.data = data
        if self.close_on_result:
            self.close()
        if self.result_callback:
            self.result_callback(data)




class DemoBitcoinVideoWidget(BitcoinVideoWidget):
    def __init__(self, parent=None, close_on_result=False,):
        super().__init__(result_callback=self.result_callback, parent=parent, close_on_result=close_on_result)

        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)

    def result_callback(self, qr_data):
        self.label_qr.setText(str(qr_data) )
