from PyQt6 import sip
from PyQt6.QtWidgets import QApplication

from bitcoin_qr_tools.gui.qr_widgets import QRCodeWidgetSVG


def test_next_svg_ignores_stale_timer_callback_after_widget_deletion() -> None:
    _app = QApplication.instance() or QApplication(["pytest", "-platform", "offscreen"])
    widget = QRCodeWidgetSVG(always_animate=True)
    widget.set_data_list(["first", "second"])
    assert widget.timer.isActive()

    sip.delete(widget)
    assert sip.isdeleted(widget)

    widget.next_svg()
    assert widget.current_index == 0
