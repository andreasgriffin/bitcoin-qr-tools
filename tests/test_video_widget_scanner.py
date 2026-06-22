import numpy as np

from bitcoin_qr_tools.gui.video_widget import (
    DEFAULT_DETECTION_VARIANTS,
    FULL_DETECTION_VARIANTS,
    DEFAULT_DETECTION_MAX_WORKERS,
    normalize_detection_variants,
)


def test_normalize_detection_variants_defaults_and_empty():
    assert normalize_detection_variants(None) == list(DEFAULT_DETECTION_VARIANTS)
    assert normalize_detection_variants([]) == [None]


def test_default_detection_variants_match_current_choice():
    assert list(DEFAULT_DETECTION_VARIANTS) == [None, (5, 11), (5, 21), (11, 35)]
    assert DEFAULT_DETECTION_MAX_WORKERS == 3


def test_default_detection_variants_are_subset_of_full():
    assert set(DEFAULT_DETECTION_VARIANTS).issubset(set(FULL_DETECTION_VARIANTS))
