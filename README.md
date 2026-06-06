# tg-ws-proxy

**Telegram MTProto WebSocket Bridge Proxy** — прокси для Telegram Desktop,
конвертирующий MTProto поверх TCP в MTProto поверх WebSocket.

Форк оригинального проекта [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy),
переписанный с Python на Rust.

## Возможности

- Проксирование MTProto через WebSocket (RFC 6455) — без внешних WS-библиотек
- Поддержка Fake TLS — маскировка под HTTPS-трафик
- Поддержка PROXY protocol v1
- Obfuscated MTProto handshake (как в MTProx)
- CF Worker / Cloudflare Proxy fallback chain
- Автоматическое обновление списка доменов Cloudflare
- Blacklist DC при недоступности
- Балансировка по пулу WebSocket-соединений
- Автоматическая проверка обновлений с GitHub
- Per-session статистика
- GUI окно (egui) через иконку в системном трее
- Graceful shutdown по Ctrl+C

## Использование

```
tg-ws-proxy [OPTIONS]
```

### Параметры

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `--port` | `1443` | Порт для входящих подключений |
| `--host` | `127.0.0.1` | Интерфейс для прослушивания |
| `--secret` | — | Secret-ключ (hex) для MTProto |
| `--dc-ip` | — | Принудительный IP для DC (например `2:1.2.3.4`) |
| `--config` | — | Путь к TOML-конфигу |

### Config file (`config.toml`)

```toml
host = "0.0.0.0"
port = 1443
secret = "ee"  # hex-encoded secret
```

## Сборка

```bash
cargo build --release
```

Бинарник будет в `target/release/tg-ws-proxy.exe`.

## Зависимости

- Rust edition 2024
- Tokio (асинхронный рантайм)
- eframe/egui (GUI)
- tokio-native-tls (TLS)
- Реализация WebSocket, Fake TLS и MTProto — собственная, без внешних библиотек

## Лицензия

MIT — как и оригинал.
