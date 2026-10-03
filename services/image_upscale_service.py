from __future__ import annotations

import io
import logging
import re

from PIL import Image, ImageFilter, ImageOps

from utils.diagnostics import diagnostic_excerpt

logger = logging.getLogger(__name__)

_SIZE_RE = re.compile(r"^(\d{2,5})x(\d{2,5})$")
_MAX_SIDE = 8192


def _target_size(requested_size: object) -> tuple[int, int] | None:
    text = str(requested_size or "").strip().lower()
    match = _SIZE_RE.fullmatch(text)
    if match is None:
        return None
    width = int(match.group(1))
    height = int(match.group(2))
    if width <= 0 or height <= 0 or width > _MAX_SIDE or height > _MAX_SIDE:
        return None
    return width, height


def _fit_image_to_requested_size(image_data: bytes, target: tuple[int, int]) -> bytes:
    with Image.open(io.BytesIO(image_data)) as source:
        transposed = ImageOps.exif_transpose(source)
        try:
            source_size = [transposed.size[0], transposed.size[1]]
            if transposed.size == target:
                return image_data
            image = transposed
            converted = None
            if image.mode not in {"RGB", "RGBA"}:
                converted = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                image = converted
            resized = image.resize(target, Image.Resampling.LANCZOS)
            sharpened = resized.filter(ImageFilter.UnsharpMask(radius=1.2, percent=80, threshold=2))
            try:
                output = io.BytesIO()
                sharpened.save(output, format="PNG", optimize=True)
                result = output.getvalue()
            finally:
                sharpened.close()
                resized.close()
                if converted is not None:
                    converted.close()
        finally:
            if transposed is not source:
                transposed.close()
    logger.info({
        "event": "image_resize_done",
        "source_size": source_size,
        "target_size": [target[0], target[1]],
        "source_bytes": len(image_data),
        "result_bytes": len(result),
    })
    return result


def upscale_image_if_needed(image_data: bytes, requested_size: object) -> bytes:
    if not image_data:
        return image_data
    target = _target_size(requested_size)
    if target is None:
        return image_data
    try:
        return _fit_image_to_requested_size(image_data, target)
    except Exception as exc:
        logger.warning({
            "event": "image_resize_failed",
            "target_size": [target[0], target[1]],
            "error": diagnostic_excerpt(exc),
        })
        return image_data
