import mss
import numpy as np
import pygame


class ScreenCamera:
    def __init__(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def _numpy_to_surface(self, numpy_image: np.ndarray) -> pygame.Surface:
        # Convert numpy image (RGB) to pygame surface
        return pygame.surfarray.make_surface(numpy_image.transpose((1, 0, 2)))

    def get_image(self):
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # capture the first monitor
            sct_img = sct.grab(monitor)

        image = np.array(sct_img)

        # Convert BGRA to RGB by reordering the channels
        image = image[:, :, [2, 1, 0]]  # Rearrange BGR to RGB

        # Convert numpy image to surface for drawing
        surface = self._numpy_to_surface(image)
        surface = pygame.transform.flip(surface, True, False)
        return surface

    def __del__(self):
        self.stop()
