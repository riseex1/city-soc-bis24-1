"""Связь с Транспортом (NATS) для синхронного Flask-приложения.

NATS-клиент асинхронный, поэтому он живёт в отдельном потоке со своим циклом asyncio.
Если Транспорт недоступен, публикации тихо отбрасываются (журнал в stdout всё равно пишется),
а клиент переподключается сам.
"""

import asyncio
import json
import threading
from collections.abc import Callable

Handler = Callable[[str, dict], None]


class MemoryBus:
    """Шина в памяти — для тестов и запуска без Транспорта."""

    def __init__(self) -> None:
        self.published: list[tuple[str, dict]] = []
        self.handlers: list[tuple[str, Handler]] = []

    def publish(self, subject: str, payload: dict) -> None:
        self.published.append((subject, payload))
        for pattern, handler in self.handlers:
            if subject_matches(pattern, subject):
                handler(subject, payload)

    def subscribe(self, pattern: str, handler: Handler) -> None:
        self.handlers.append((pattern, handler))


def subject_matches(pattern: str, subject: str) -> bool:
    """Сопоставление тем NATS: `*` — одно слово, `>` — всё остальное."""
    p, s = pattern.split("."), subject.split(".")
    for i, part in enumerate(p):
        if part == ">":
            return len(s) > i
        if i >= len(s) or (part != "*" and part != s[i]):
            return False
    return len(p) == len(s)


class NatsBus:
    def __init__(self, url: str, token: str | None, name: str) -> None:
        self.url, self.token, self.name = url, token, name
        self.handlers: list[tuple[str, Handler]] = []
        self._nc = None
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._run, name="nats", daemon=True).start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._connect_forever())
        self._loop.run_forever()

    async def _connect_forever(self) -> None:
        import nats

        async def quiet(_err) -> None:
            """Ошибки связи не печатаем трассировками: клиент переподключается сам."""

        while self._nc is None:
            try:
                self._nc = await nats.connect(
                    self.url,
                    token=self.token or None,
                    name=self.name,
                    connect_timeout=2,
                    allow_reconnect=True,
                    max_reconnect_attempts=-1,
                    reconnect_time_wait=2,
                    error_cb=quiet,
                )
            except Exception:  # noqa: BLE001 — Транспорт ещё не запущен, пробуем снова
                await asyncio.sleep(3)
        for pattern, handler in self.handlers:
            await self._subscribe(pattern, handler)

    async def _subscribe(self, pattern: str, handler: Handler) -> None:
        async def cb(msg) -> None:
            try:
                payload = json.loads(msg.data)
            except ValueError:
                return  # мусор в шине не роняет сервис
            if isinstance(payload, dict):
                try:
                    await asyncio.to_thread(handler, msg.subject, payload)
                except Exception as exc:  # noqa: BLE001 — ошибка обработчика не должна рвать подписку
                    print(
                        f'{{"level":"ERROR","event":"service.error","msg":"обработчик {msg.subject}: {type(exc).__name__}"}}',
                        flush=True,
                    )

        await self._nc.subscribe(pattern, cb=cb)

    def publish(self, subject: str, payload: dict) -> None:
        nc = self._nc
        if nc is None or not nc.is_connected:
            return
        data = json.dumps(payload, ensure_ascii=False).encode()
        asyncio.run_coroutine_threadsafe(nc.publish(subject, data), self._loop)

    def subscribe(self, pattern: str, handler: Handler) -> None:
        self.handlers.append((pattern, handler))
        if self._nc is not None:
            asyncio.run_coroutine_threadsafe(self._subscribe(pattern, handler), self._loop)

    def flush(self, timeout: float = 2) -> None:
        if self._nc is not None:
            asyncio.run_coroutine_threadsafe(self._nc.flush(), self._loop).result(timeout)
