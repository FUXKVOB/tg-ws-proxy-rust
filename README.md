# tg-ws-proxy

**Telegram MTProto WebSocket Bridge Proxy** — прокси для Telegram Desktop,
конвертирующий MTProto поверх TCP в MTProto поверх WebSocket.

Основан на [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy),
с критическими участками, переписанными на Rust (PyO3) для производительности.

## Возможности

- Проксирование MTProto через WebSocket (RFC 6455)
- Поддержка Fake TLS — маскировка под HTTPS-трафик
- Поддержка PROXY protocol v1
- Obfuscated MTProto handshake (Abridged / Intermediate / Padded Intermediate)
- CF Worker / Cloudflare Proxy / TCP fallback chain
- Автоматическое обновление списка доменов Cloudflare
- Blacklist DC при недоступности
- Балансировка по пулу WebSocket-соединений
- Rust-ускорение: XOR-маскировка + MsgSplitter (AES-CTR + MTProto packet splitter)
- Tray UI (Windows / macOS / Linux)
- Graceful shutdown

## Использование

```
tg-ws-proxy [OPTIONS]
```

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `--port` | `1443` | Порт для входящих подключений |
| `--host` | `127.0.0.1` | Интерфейс для прослушивания |
| `--secret` | — | Secret-ключ (hex) для MTProto |
| `--dc-ip` | — | Принудительный IP для DC (например `2:1.2.3.4`) |
| `--fake-tls-domain` | — | Домен для Fake TLS (ee-secret) |
| `--cfproxy-domain` | — | Пользовательский CF-домен |
| `--cfproxy-worker-domain` | — | Cloudflare Worker домен |
| `--pool-size` | `4` | Размер пула WS-соединений |
| `--buf-kb` | `256` | Буфер сокета (KB) |
| `--proxy-protocol` | — | PROXY protocol v1 |
| `--shutdown-timeout` | `10` | Таймаут graceful shutdown (сек) |

## Сборка

```bash
# Python + Rust (PyO3) — требуется Rust toolchain + Python 3.11+
pip install maturin
maturin develop --release
pip install .
```

Бинарный файл собирается через PyInstaller:
```bash
pyinstaller packaging/windows.spec --noconfirm
```

## Rust-компоненты

| Модуль | Назначение |
|--------|-----------|
| `xor_mask` | XOR-маскировка WebSocket фреймов (RFC 6455) — SIMD через u32 |
| `MsgSplitter` | AES-256-CTR дешифровка + разбор MTProto пакетов (Abridged/Intermediate/Padded) |

## Зависимости

- Python 3.11+
- Rust edition 2024 (PyO3)
- Tokio не используется — asyncio (Python)
- GUI: CustomTkinter / rumps / pystray

## Лицензия

MIT
