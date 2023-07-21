from .qr_qui import VideoWidget
from .bitcoin_qr import *
from PySide2 import QtWidgets
from typing import Dict


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
        self.result_callback = result_callback
        self.close_on_result = close_on_result
        
        self.meta_data_handler = MetaDataHandler(self.network)
        

    def qr_data_callback(self, qr_data):
        self.meta_data_handler.add(qr_data.decode("utf-8"))
            
        if self.meta_data_handler.is_complete():
            if self.close_on_result:
                self.close()
            if self.result_callback:
                self.result_callback(self.meta_data_handler.get_complete_data())

            




class DemoBitcoinVideoWidget(BitcoinVideoWidget):
    def __init__(self, parent=None, close_on_result=False,):
        super().__init__(result_callback=self.result_callback, parent=parent, close_on_result=close_on_result)

        self.label_qr = QtWidgets.QTextEdit()

        self.layout().addWidget(self.label_qr)

    def result_callback(self, qr_data):
        self.label_qr.setText(str(qr_data) )
