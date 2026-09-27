from __future__ import annotations

from io import BytesIO
from typing import Any, Iterator

from PIL import Image

from services.image_failure import image_failure
from services.protocol.conversation import (
    ConversationRequest,
    ImageGenerationError,
    collect_image_outputs,
    count_text_tokens,
    encode_images,
    ensure_supported_image_model,
    stream_image_chunks,
    stream_image_outputs_with_pool,
)
from utils.helper import run_until_image_stop
from utils.image_tokens import count_image_inputs_tokens, count_image_output_items_tokens, image_usage


def _composite_mask(
    images: list[tuple[bytes, str, str]],
    masks: list[tuple[bytes, str, str]],
) -> list[tuple[bytes, str, str]]:
    """将 mask 的 alpha 通道合成到图片中，标识需要编辑的区域。
    
    mask 的透明区域（低 alpha）= 需要编辑的区域，
    mask 的不透明区域（高 alpha）= 保留的区域。
    如果无 mask 则返回原图。
    """
    if not masks:
        return images
    result: list[tuple[bytes, str, str]] = []
    for i, (data, filename, mime_type) in enumerate(images):
        mask_data = masks[i][0] if i < len(masks) else masks[-1][0]
        img = Image.open(BytesIO(data)).convert("RGBA")
        mask_img = Image.open(BytesIO(mask_data))
        if mask_img.mode == "RGBA":
            alpha = mask_img.split()[3]
        elif mask_img.mode == "L":
            alpha = mask_img
        else:
            alpha = mask_img.convert("L")
        alpha = alpha.resize(img.size, Image.LANCZOS)
        img.putalpha(alpha)
        buf = BytesIO()
        img.save(buf, format="PNG")
        result.append((buf.getvalue(), filename, "image/png"))
    return result


def _require_edit_images(images: list) -> None:
    if any(item and item[0] for item in images):
        return
    raise ImageGenerationError(
        "image is required",
        failure=image_failure("invalid_image_input"),
    )


def _require_readable_edit_inputs(
    images: list[tuple[bytes, str, str]],
    masks: list[tuple[bytes, str, str]],
) -> None:
    """Reject an unreadable mask before the stream opens. Composition itself waits."""
    if not masks:
        return
    try:
        for item in (*images, *masks):
            data = item[0] if item else b""
            if not data:
                continue
            with Image.open(BytesIO(data)) as img:
                img.verify()
    except (OSError, ValueError) as exc:
        raise ImageGenerationError(
            "image is invalid",
            failure=image_failure("invalid_image_input"),
        ) from exc


def _prepared_edit_images(body: dict[str, Any]) -> list[tuple[bytes, str, str]]:
    try:
        return _composite_mask(body.get("images") or [], body.get("mask") or [])
    except (OSError, ValueError) as exc:
        raise ImageGenerationError(
            "image is invalid",
            failure=image_failure("invalid_image_input"),
        ) from exc


def _edit_outputs(
    body: dict[str, Any],
    images: list[tuple[bytes, str, str]] | None = None,
):
    prompt = str(body.get("prompt") or "")
    if images is None:
        images = run_until_image_stop(lambda: _prepared_edit_images(body))
    model = str(body.get("model") or "gpt-image-2")
    size = body.get("size")
    quality = str(body.get("quality") or "auto")
    encoded_images = run_until_image_stop(lambda: encode_images(images))
    if not encoded_images:
        raise ImageGenerationError(
            "image is required",
            failure=image_failure("invalid_image_input"),
        )
    outputs = stream_image_outputs_with_pool(ConversationRequest(
        prompt=prompt,
        model=model,
        n=int(body.get("n") or 1),
        size=size,
        quality=quality,
        response_format=str(body.get("response_format") or "b64_json"),
        base_url=str(body.get("base_url") or "") or None,
        images=encoded_images,
        message_as_error=True,
        progress_callback=body.get("progress_callback"),
        session_checkpoint=body.get("session_checkpoint"),
        call_id=str(body.get("_call_id") or ""),
        trace_image_perf=bool(body.get("_trace_image_perf")),
    ))
    return prompt, model, images, size, quality, outputs


def _stream_edit(
    body: dict[str, Any],
    images: list[tuple[bytes, str, str]] | None = None,
) -> Iterator[dict[str, Any]]:
    prompt, model, images, size, quality, outputs = _edit_outputs(body, images)
    input_text_tokens = count_text_tokens(prompt, model)
    input_image_tokens = count_image_inputs_tokens(images, model)
    yield from stream_image_chunks(
        outputs,
        event_prefix="image_edit",
        partial_images=body.get("partial_images"),
        usage_builder=lambda data: image_usage(
            input_text_tokens=input_text_tokens,
            input_image_tokens=input_image_tokens,
            output_tokens=count_image_output_items_tokens(data, size, quality),
        ),
    )


def handle(body: dict[str, Any]) -> dict[str, Any] | Iterator[dict[str, Any]]:
    _require_edit_images(body.get("images") or [])
    model = str(body.get("model") or "gpt-image-2").strip() or "gpt-image-2"
    ensure_supported_image_model(model)
    if body.get("stream"):
        _require_readable_edit_inputs(body.get("images") or [], body.get("mask") or [])
        return _stream_edit(body)
    prompt, model, images, size, quality, outputs = _edit_outputs(body)
    result = collect_image_outputs(outputs, result_callback=body.get("_image_result_callback"))
    result["usage"] = image_usage(
        input_text_tokens=count_text_tokens(prompt, model),
        input_image_tokens=count_image_inputs_tokens(images, model),
        output_tokens=count_image_output_items_tokens(result.get("data"), size, quality),
    )
    return result
