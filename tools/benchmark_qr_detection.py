import argparse
import json
import logging
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import bdkpython as bdk
import cv2
import numpy as np
from PyQt6 import QtCore, QtWidgets

from bitcoin_qr_tools.data import Data
from bitcoin_qr_tools.gui.video_widget import (
    BarcodeData,
    DEFAULT_DETECTION_VARIANTS,
    FULL_DETECTION_VARIANTS,
    DetectionVariant,
    preprocess_for_qr_detection,
    threaded_list,
    VideoWidget,
)
from bitcoin_qr_tools.qr_generator import QRGenerator
from bitcoin_qr_tools.unified_encoder import QrExportTypes, UnifiedEncoder

logger = logging.getLogger(__name__)

DEFAULT_PSBT = (
    "cHNidP8BAHEBAAAAAXgQzjk+DTWQTPUtRMbYiheC0jfbipvw+jQ5lidmyABjAAAAAAD9////AgDh9QUAAAAAFgAU"
    "bBuOQOlcnz8vpruh2Kb3CFr4vlhkEQ2PAAAAABYAFN1n2hvBWYzshD42xwQzy9XYoji3BAEAAAABAKoCAAAAAAEBAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BQKYAAEB/////wIA+QKVAAAAABYAFLlHwN6VXNLM381b"
    "MxmNJlaDTQzVAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkBIAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBHwD5ApUAAAAAFgAUuUfA3pVc0szfzVszGY0mVoNNDNUiBgISCnRxeO"
    "xzC0MgK01AmiIRLrgS1AyIqKeBkdwL+nt/6RikLG3TVAAAgAEAAIAAAACAAAAAAAAAAAAAACICAlQcwExiTUk9f7o"
    "lLkwPlQpiregRHc9jXXFJBlMoucgNGKQsbdNUAACAAQAAgAAAAIAAAAAAAQAAAAA="
)


@dataclass
class BenchmarkConfig:
    name: str
    variants: list[DetectionVariant]
    workers: int | None


@dataclass
class BenchmarkResult:
    source: str
    config_name: str
    workers: int | None
    variants: list[DetectionVariant]
    frames: int
    successes: int
    success_rate: float
    total_wall_ms: float
    mean_scan_ms: float
    median_scan_ms: float
    min_scan_ms: float
    max_scan_ms: float
    p95_scan_ms: float
    effective_fps: float
    decodes_per_second: float


def parse_variant(token: str) -> DetectionVariant:
    lowered = token.strip().lower()
    if lowered in {"none", "raw", "original"}:
        return None

    normalized = lowered.replace("x", ",")
    parts = [part.strip() for part in normalized.split(",") if part.strip()]
    if len(parts) != 2:
        raise ValueError(f"Invalid variant token: {token}")
    return int(parts[0]), int(parts[1])


def parse_config(spec: str) -> BenchmarkConfig:
    parts = [part.strip() for part in spec.split(";") if part.strip()]
    if not parts:
        raise ValueError("Empty config spec")

    name = parts[0]
    workers: int | None = None
    variants: list[DetectionVariant] | None = None
    for part in parts[1:]:
        key, _, value = part.partition("=")
        if not key or not value:
            raise ValueError(f"Invalid config part: {part}")
        key = key.strip().lower()
        value = value.strip()
        if key == "workers":
            workers = None if value.lower() == "none" else int(value)
        elif key == "variants":
            variants = [parse_variant(token) for token in value.split(",")]
        else:
            raise ValueError(f"Unknown config option: {key}")

    if variants is None:
        raise ValueError("Config requires variants=...")

    return BenchmarkConfig(name=name, variants=variants, workers=workers)


def default_configs() -> list[BenchmarkConfig]:
    default_variants = list(FULL_DETECTION_VARIANTS)
    return [
        BenchmarkConfig("raw-only", [None], 1),
        BenchmarkConfig("raw-plus-1", [None, (5, 11)], 1),
        BenchmarkConfig("raw-plus-2", [None, (5, 11), (5, 21)], 2),
        BenchmarkConfig("full-serial", default_variants, 1),
        BenchmarkConfig("full-2-workers", default_variants, 2),
        BenchmarkConfig("full-3-workers", default_variants, 3),
        BenchmarkConfig("full-all-workers", default_variants, len(default_variants)),
    ]


def build_fragment(payload_format: str, fragment_index: int) -> str:
    if payload_format == "text":
        return DEFAULT_PSBT
    data = Data.from_str(DEFAULT_PSBT, network=bdk.Network.REGTEST)
    if payload_format == "ur":
        return UnifiedEncoder.generate_fragments_for_qr(data, qr_export_type=QrExportTypes.ur)[fragment_index]
    if payload_format == "bbqr":
        return UnifiedEncoder.generate_fragments_for_qr(data, qr_export_type=QrExportTypes.bbqr)[
            fragment_index
        ]
    raise ValueError(f"Unsupported payload format: {payload_format}")


def pil_to_rgb_array(image) -> np.ndarray:
    rgb = image.convert("RGB")
    return np.array(rgb)


def generated_qr_source(payload_format: str, fragment_index: int, scale: int) -> tuple[str, np.ndarray, str]:
    fragment = build_fragment(payload_format=payload_format, fragment_index=fragment_index)
    image = QRGenerator.create_qr_PILimage(fragment, scale=scale)
    return f"generated:{payload_format}:{fragment_index}", pil_to_rgb_array(image), fragment


def image_sources(paths: list[Path]) -> list[tuple[str, np.ndarray, str | None]]:
    sources: list[tuple[str, np.ndarray, str | None]] = []
    for path in paths:
        array = cv2.cvtColor(cv2.imread(str(path)), cv2.COLOR_BGR2RGB)
        sources.append((str(path), array, None))
    return sources


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def is_expected_success(
    barcode_data: bytes,
    expected_text: str | None = None,
    expected_prefix: str | None = None,
) -> bool:
    decoded = barcode_data.decode("utf-8", errors="ignore")
    if expected_text is None:
        if expected_prefix is None:
            return bool(decoded)
        return decoded.startswith(expected_prefix)
    return decoded == expected_text


class BarcodeScanner:
    def __init__(self):
        self.cv2 = None
        self.pyzbar = None
        self.detection_variants = list(DEFAULT_DETECTION_VARIANTS)
        self.max_workers = None
        try:
            from pyzbar import pyzbar

            self.pyzbar = pyzbar
            logger.info("Load pyzbar successful")
        except Exception:
            logger.info("Could not load pyzbar. Trying to load fallback cv2")
            import cv2 as cv2_fallback

            self.cv2 = cv2_fallback

    def set_detection_config(
        self,
        detection_variants: list[DetectionVariant] | None = None,
        max_workers: int | None = None,
    ) -> None:
        self.detection_variants = (
            list(DEFAULT_DETECTION_VARIANTS) if detection_variants is None else list(detection_variants)
        )
        self.max_workers = max_workers

    def get_barcodes(self, array: np.ndarray) -> list[BarcodeData]:
        if self.pyzbar:
            decoded_codes = self.pyzbar.decode(array)
            return [BarcodeData(data=decoded.data, rect=decoded.rect) for decoded in decoded_codes]
        if self.cv2:
            array = self.cv2.transpose(array)
            array = self.cv2.cvtColor(array, self.cv2.COLOR_RGB2BGR)
            detector = self.cv2.QRCodeDetector()
            val, points, _straight_qrcode = detector.detectAndDecode(array)

            barcodes = []
            if val and points is not None:
                points = points[0]
                y, x, w, h = self.cv2.boundingRect(points.astype(np.int32))
                rect = (x, y, w, h)
                barcodes.append(BarcodeData(val.encode(), rect))

            return barcodes
        return []

    def detect_with_variants(
        self, array_original: np.ndarray
    ) -> tuple[list[BarcodeData], list[list[BarcodeData]]]:
        def transform_and_detect(values: DetectionVariant) -> list[BarcodeData]:
            if values is None:
                return self.get_barcodes(array_original)
            gauss_kernel_size, thres = values
            try:
                return self.get_barcodes(
                    preprocess_for_qr_detection(
                        array_original.copy(), gauss_kernel_size=gauss_kernel_size, threshold_blockSize=thres
                    )
                )
            except Exception:
                return []

        list_of_barcodes = threaded_list(
            transform_and_detect, self.detection_variants, max_workers=self.max_workers
        )
        return sum(list_of_barcodes, []), list_of_barcodes


def benchmark_array(
    scanner: BarcodeScanner,
    source_name: str,
    array: np.ndarray,
    expected_text: str | None,
    expected_prefix: str | None,
    config: BenchmarkConfig,
    iterations: int,
) -> BenchmarkResult:
    scanner.set_detection_config(detection_variants=config.variants, max_workers=config.workers)

    scan_times_ms: list[float] = []
    successes = 0
    wall_start = time.perf_counter()
    for _ in range(iterations):
        scan_start = time.perf_counter()
        barcodes, _list_of_barcodes = scanner.detect_with_variants(array)
        scan_times_ms.append((time.perf_counter() - scan_start) * 1000)
        if any(is_expected_success(barcode.data, expected_text, expected_prefix) for barcode in barcodes):
            successes += 1
    total_wall_ms = (time.perf_counter() - wall_start) * 1000

    frames = len(scan_times_ms)
    success_rate = successes / frames if frames else 0.0
    effective_fps = frames / (total_wall_ms / 1000) if total_wall_ms else 0.0
    decodes_per_second = successes / (total_wall_ms / 1000) if total_wall_ms else 0.0

    return BenchmarkResult(
        source=source_name,
        config_name=config.name,
        workers=config.workers,
        variants=config.variants,
        frames=frames,
        successes=successes,
        success_rate=success_rate,
        total_wall_ms=total_wall_ms,
        mean_scan_ms=statistics.fmean(scan_times_ms),
        median_scan_ms=statistics.median(scan_times_ms),
        min_scan_ms=min(scan_times_ms),
        max_scan_ms=max(scan_times_ms),
        p95_scan_ms=percentile(scan_times_ms, 0.95),
        effective_fps=effective_fps,
        decodes_per_second=decodes_per_second,
    )


class CameraBenchmarkWidget(VideoWidget):
    def __init__(
        self,
        configs: list[BenchmarkConfig],
        duration_s: float,
        rounds: int,
        expected_text: str | None,
        expected_prefix: str | None,
        output_json: Path | None,
        camera_index: int | None,
        close_on_finish: bool = True,
    ):
        self.configs = configs
        self.duration_s = duration_s
        self.rounds = rounds
        self.expected_text = expected_text
        self.expected_prefix = expected_prefix
        self.output_json = output_json
        self.close_on_finish = close_on_finish
        self.results: list[BenchmarkResult] = []
        self._finished = False
        self._config_index = 0
        self._round_index = 1
        self._config_started_at = 0.0
        self._scan_times_ms: list[float] = []
        self._successes = 0
        self._last_scan_ms = 0.0
        super().__init__()
        self.setWindowTitle("QR Detection Benchmark")
        self.status_label = QtWidgets.QLabel()
        self.status_label.setWordWrap(True)
        self._layout.insertWidget(1, self.status_label)
        if camera_index is not None:
            self.select_camera(camera_index)
        self._start_current_config()

    @property
    def active_config(self) -> BenchmarkConfig:
        return self.configs[self._config_index]

    def select_camera(self, camera_index: int) -> None:
        for index in range(self.combo_cameras.count()):
            camera = self.combo_cameras.itemData(index)
            if getattr(camera, "device_index", None) == camera_index:
                self.combo_cameras.setCurrentIndex(index)
                return
        if 0 <= camera_index < self.combo_cameras.count():
            self.combo_cameras.setCurrentIndex(camera_index)

    def _start_current_config(self) -> None:
        config = self.active_config
        self.set_detection_config(detection_variants=config.variants, max_workers=config.workers)
        self._scan_times_ms = []
        self._successes = 0
        self._last_scan_ms = 0.0
        self._config_started_at = time.perf_counter()
        self._update_status()

    def _current_result(self) -> BenchmarkResult:
        total_wall_ms = (time.perf_counter() - self._config_started_at) * 1000
        frames = len(self._scan_times_ms)
        config = self.active_config
        success_rate = self._successes / frames if frames else 0.0
        effective_fps = frames / (total_wall_ms / 1000) if total_wall_ms else 0.0
        decodes_per_second = self._successes / (total_wall_ms / 1000) if total_wall_ms else 0.0
        return BenchmarkResult(
            source="camera",
            config_name=config.name,
            workers=config.workers,
            variants=config.variants,
            frames=frames,
            successes=self._successes,
            success_rate=success_rate,
            total_wall_ms=total_wall_ms,
            mean_scan_ms=statistics.fmean(self._scan_times_ms) if self._scan_times_ms else 0.0,
            median_scan_ms=statistics.median(self._scan_times_ms) if self._scan_times_ms else 0.0,
            min_scan_ms=min(self._scan_times_ms) if self._scan_times_ms else 0.0,
            max_scan_ms=max(self._scan_times_ms) if self._scan_times_ms else 0.0,
            p95_scan_ms=percentile(self._scan_times_ms, 0.95),
            effective_fps=effective_fps,
            decodes_per_second=decodes_per_second,
        )

    def _update_status(self) -> None:
        config = self.active_config
        elapsed_s = time.perf_counter() - self._config_started_at if self._config_started_at else 0.0
        remaining_s = max(0.0, self.duration_s - elapsed_s)
        workers = config.workers if config.workers is not None else "auto"
        self.status_label.setText(
            "\n".join(
                [
                    f"Round {self._round_index}/{self.rounds}",
                    f"Config: {config.name}",
                    f"Workers: {workers}",
                    f"Variants: {config.variants}",
                    f"Frames: {len(self._scan_times_ms)}  Hits: {self._successes}",
                    f"Last scan: {self._last_scan_ms:.2f} ms  Remaining: {remaining_s:.1f}s",
                    "Close the window to stop early.",
                ]
            )
        )

    def _advance(self) -> None:
        self.results.append(self._current_result())
        self._config_index += 1
        if self._config_index >= len(self.configs):
            self._config_index = 0
            self._round_index += 1
        if self._round_index > self.rounds:
            self._finish()
            return
        self._start_current_config()

    def _finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        self.timer.stop()
        aggregated_results = aggregate_results(self.results) if self.rounds > 1 else self.results
        print_summary(aggregated_results)
        if self.output_json:
            self.output_json.write_text(
                json.dumps([asdict(result) for result in aggregated_results], indent=2),
                encoding="utf-8",
            )
        if self.close_on_finish:
            QtCore.QTimer.singleShot(0, self.close)

    def update_frame(self):
        if self._finished:
            return
        scan_started_at = time.perf_counter()
        super().update_frame()
        self._last_scan_ms = (time.perf_counter() - scan_started_at) * 1000
        if self.current_camera is None:
            self._update_status()
            return
        self._scan_times_ms.append(self._last_scan_ms)
        if self.last_selected_barcode and is_expected_success(
            self.last_selected_barcode.data,
            self.expected_text,
            self.expected_prefix,
        ):
            self._successes += 1
        self._update_status()
        if (time.perf_counter() - self._config_started_at) >= self.duration_s:
            self._advance()

    def closeEvent(self, event):
        if not self._finished and self._scan_times_ms:
            self.results.append(self._current_result())
            aggregated_results = aggregate_results(self.results) if self.rounds > 1 else self.results
            print_summary(aggregated_results)
            if self.output_json:
                self.output_json.write_text(
                    json.dumps([asdict(result) for result in aggregated_results], indent=2),
                    encoding="utf-8",
                )
            self._finished = True
        super().closeEvent(event)


def aggregate_results(results: list[BenchmarkResult]) -> list[BenchmarkResult]:
    grouped: dict[tuple[str, str], list[BenchmarkResult]] = {}
    for result in results:
        grouped.setdefault((result.source, result.config_name), []).append(result)

    aggregated: list[BenchmarkResult] = []
    for (source, config_name), grouped_results in grouped.items():
        total_frames = sum(result.frames for result in grouped_results)
        total_successes = sum(result.successes for result in grouped_results)
        total_wall_ms = sum(result.total_wall_ms for result in grouped_results)
        mean_scan_ms = (
            sum(result.mean_scan_ms * result.frames for result in grouped_results) / total_frames
            if total_frames
            else 0.0
        )
        aggregated.append(
            BenchmarkResult(
                source=source,
                config_name=config_name,
                workers=grouped_results[0].workers,
                variants=grouped_results[0].variants,
                frames=total_frames,
                successes=total_successes,
                success_rate=total_successes / total_frames if total_frames else 0.0,
                total_wall_ms=total_wall_ms,
                mean_scan_ms=mean_scan_ms,
                median_scan_ms=statistics.fmean([result.median_scan_ms for result in grouped_results]),
                min_scan_ms=min(result.min_scan_ms for result in grouped_results),
                max_scan_ms=max(result.max_scan_ms for result in grouped_results),
                p95_scan_ms=statistics.fmean([result.p95_scan_ms for result in grouped_results]),
                effective_fps=total_frames / (total_wall_ms / 1000) if total_wall_ms else 0.0,
                decodes_per_second=total_successes / (total_wall_ms / 1000) if total_wall_ms else 0.0,
            )
        )
    return aggregated


def print_summary(results: Iterable[BenchmarkResult]) -> None:
    grouped: dict[str, list[BenchmarkResult]] = {}
    for result in results:
        grouped.setdefault(result.source, []).append(result)

    for source, source_results in grouped.items():
        print(f"\nSource: {source}")
        print("config                workers  success%  mean_ms  median_ms  p95_ms  fps    decodes/s  frames")
        print("--------------------  -------  --------  -------  ---------  ------  -----  ---------  ------")
        for result in sorted(
            source_results,
            key=lambda item: (-item.success_rate, item.mean_scan_ms, -item.effective_fps),
        ):
            workers = "auto" if result.workers is None else str(result.workers)
            print(
                f"{result.config_name:<20}  {workers:>7}  {result.success_rate * 100:>8.1f}  "
                f"{result.mean_scan_ms:>7.2f}  {result.median_scan_ms:>9.2f}  {result.p95_scan_ms:>6.2f}  "
                f"{result.effective_fps:>5.1f}  {result.decodes_per_second:>9.1f}  {result.frames:>6}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark QR detection settings with a live camera or test images."
    )
    parser.add_argument(
        "--image", action="append", default=[], help="Benchmark an image file. Can be repeated."
    )
    parser.add_argument(
        "--config",
        action="append",
        default=[],
        help="Custom config like: raw-only;workers=1;variants=none or full;workers=3;variants=none,5x11,5x21",
    )
    parser.add_argument("--iterations", type=int, default=150, help="Image benchmark iterations per config.")
    parser.add_argument(
        "--camera-index", type=int, help="Run a live camera benchmark instead of an image benchmark."
    )
    parser.add_argument("--duration-s", type=float, default=12.0, help="Seconds per config in camera mode.")
    parser.add_argument(
        "--rounds", type=int, default=1, help="How many full config sweeps to run in camera mode."
    )
    parser.add_argument("--payload-format", choices=["text", "ur", "bbqr"], default="text")
    parser.add_argument("--fragment-index", type=int, default=0)
    parser.add_argument("--qr-scale", type=int, default=8)
    parser.add_argument("--expect-exact", help="Only count exact decoded matches as success.")
    parser.add_argument("--expect-prefix", help="Only count decodes with this prefix as success.")
    parser.add_argument("--output-json", type=Path, help="Optional path to write raw results as JSON.")
    parser.add_argument("--log-level", default="WARNING")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.WARNING))

    configs = [parse_config(spec) for spec in args.config] if args.config else default_configs()
    scanner = BarcodeScanner()
    results: list[BenchmarkResult] = []

    if args.camera_index is not None:
        expected_text = args.expect_exact if args.expect_exact else None
        expected_prefix = args.expect_prefix
        app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
        widget = CameraBenchmarkWidget(
            configs=configs,
            duration_s=args.duration_s,
            rounds=args.rounds,
            expected_text=expected_text,
            expected_prefix=expected_prefix,
            output_json=args.output_json,
            camera_index=args.camera_index,
        )
        widget.show()
        app.exec()
        return
    else:
        if args.image:
            sources = image_sources([Path(image) for image in args.image])
        else:
            sources = [generated_qr_source(args.payload_format, args.fragment_index, args.qr_scale)]

        for source_name, array, expected in sources:
            for config in configs:
                logger.info("Benchmarking %s with %s", source_name, config.name)
                results.append(
                    benchmark_array(
                        scanner=scanner,
                        source_name=source_name,
                        array=array,
                        expected_text=expected,
                        expected_prefix=args.expect_prefix,
                        config=config,
                        iterations=args.iterations,
                    )
                )

    aggregated_results = aggregate_results(results) if args.rounds > 1 else results
    print_summary(aggregated_results)

    if args.output_json:
        args.output_json.write_text(
            json.dumps([asdict(result) for result in aggregated_results], indent=2), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
