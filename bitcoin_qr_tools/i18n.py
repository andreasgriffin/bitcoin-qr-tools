import logging

from PyQt6.QtCore import QCoreApplication

logger = logging.getLogger(__name__)


# this function must eb named identical to QCoreApplication.translate
# otherwise lupdate doesnt recognize it
def translate(context, s) -> str:
    return QCoreApplication.translate(context, s)
