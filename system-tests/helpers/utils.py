import asyncio
from collections.abc import Awaitable, Callable
from http import HTTPStatus
from typing import Any

import aiohttp

POLL_SECONDS = 0.5


async def wait_until(
    check: Callable[[], Awaitable[bool]], timeout: float, description: str
) -> None:
    try:
        async with asyncio.timeout(timeout):
            while not await check():
                await asyncio.sleep(POLL_SECONDS)
    except TimeoutError:
        raise TimeoutError(f"{description} not within {timeout}s") from None


async def request_json(url: str, **kwargs: Any) -> dict[str, Any]:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, **kwargs) as response:
            if response.status != HTTPStatus.OK:
                raise RuntimeError(f"{url}: {response.status} {await response.text()}")

            return await response.json(content_type=None)
