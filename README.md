# Прототип Direct-ZTNA

> Программный прототип архитектуры защищённого удалённого доступа без промежуточного шлюза в плоскости данных, построенный для экспериментальной проверки концепции «прямые по-сеансовые соединения клиент–сервис под централизованным управлением политик».

---

## Содержание

1. [Что такое Direct-ZTNA](#что-такое-direct-ztna)
2. [Архитектура решения](#архитектура-решения)
3. [Структура проекта](#структура-проекта)
4. [Требования](#требования)
5. [Быстрый старт](#быстрый-старт)
6. [Описание работы прототипа](#описание-работы-прототипа)
7. [Тестирование](#тестирование)
8. [Troubleshooting](#troubleshooting)
9. [Лицензия и ограничения](#лицензия-и-ограничения)

---

## Что такое Direct-ZTNA

**Direct-ZTNA** — это архитектура удалённого доступа по принципу Zero Trust, в которой:

- **Плоскость управления (control plane)** остаётся централизованной: контроллер принимает решения об аутентификации, авторизации и выдаче разрешений.
- **Плоскость данных (data plane)** не содержит постоянного транзитного шлюза: пользовательский трафик идёт **напрямую** между клиентским агентом и серверным агентом.
- Доступ предоставляется **по-сеансово** в виде краткоживущего криптографического билета (ticket), подписанного контроллером.
- Каждая сессия требует одновременного наличия двух факторов: валидного подписанного билета и предварительно распределённого симметричного ключа (PSK).

### Ключевое отличие от VPN и Gateway-ZTNA

| Архитектура | Транзитный узел в data plane | Поверхность атаки | Тракт трафика |
|-------------|------------------------------|-------------------|---------------|
| VPN | VPN-концентратор | \|U\|·\|S\| | Клиент → концентратор → сервис |
| Gateway-ZTNA | Прокси-шлюз (PEP) | \|U\| + Σ\|S(g)\| | Клиент → шлюз → сервис |
| **Direct-ZTNA** | **Нет** | **K_avg** | **Клиент → сервис (прямое)** |

---

## Архитектура решения

### Компоненты системы

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL PLANE                                     │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────────────┐      │
│  │   Mock IdP   │      │  Controller  │      │  Telemetry Server    │      │
│  │  (аутентиф.) │◄────►│   (PDP)      │◄────►│  (сбор событий)      │      │
│  └──────────────┘      └──────┬───────┘      └──────────────────────┘      │
│                               │                                             │
│                        выдаёт билеты,                                       │
│                        команды revoke                                       │
└───────────────────────────────┼─────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATA PLANE                                       │
│                                                                             │
│   ┌──────────────────┐                           ┌──────────────────┐      │
│   │  Client Agent    │◄─── TUN-шифратор (AES-256-GCM) ──►│  Server Agent    │      │
│   │  (PEP клиента)   │      (прямое соединение)   │  (PEP сервера)   │      │
│   └──────────────────┘                           └──────────────────┘      │
│          ▲                                               ▲                  │
│          │                                               │                  │
│          └────────────── защищаемый сервис ──────────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Роли компонентов

#### 1. Контроллер доступа (Policy Decision Point, PDP)

**Расположение:** control plane (не участвует в передаче пользовательского трафика).

**Функции:**
- Аутентификация пользователя через внешний IdP.
- Policy-check: проверка, разрешён ли доступ пользователю `sub` к сервису `service_id`.
- Формирование и подпись криптографического билета `AccessTicket` (Ed25519).
- Ведение реестра отозванных билетов (`Revoked`).
- Уведомление серверного агента о необходимости активации/деактивации peer.

**Ключевые endpoints:**
- `POST /access` — запрос билета.
- `POST /revoke` — отзыв доступа по `jti`.
- `GET /revoked` — получение списка отозванных идентификаторов.

**Билет (`AccessTicket`) содержит:**
- `iss` / `aud` — issuer и audience (контроллер и агент).
- `sub` — идентификатор пользователя.
- `service_id` — целевой сервис.
- `jti` — уникальный идентификатор билета (для отзыва и защиты от replay).
- `nbf` / `iat` / `exp` — временные границы валидности.
- `key_id` — ссылка на PSK в локальном хранилище агента.
- `transport` — параметры транспорта (pubkey, endpoint, allowed_ips).
- `scope` — разрешённые протокол и порт.
- `sig` — подпись Ed25519 всего payload.

**Важно:** контроллер не создаёт новый транспортный секрет при каждом запросе. Он управляет **правом на использование** заранее подготовленного ключевого материала.

#### 2. Mock IdP

**Роль:** упрощённый поставщик идентичности для прототипа.

**Логика:** reverse lookup Bearer-токена → `sub` + `attrs`. Не моделирует MFA, федерацию или непрерывную оценку контекста.

#### 3. Клиентский агент (PEP на стороне пользователя)

**Расположение:** data plane, конечная точка пользователя.

**Функции:**
- Инициирование запроса доступа.
- Локальная валидация полученного билета: подпись, audience, срок действия, отсутствие в `Revoked`.
- Проверка наличия PSK по `key_id`.
- Активация TUN-туннеля с параметрами из билета.
- Фиксация событий жизненного цикла в телеметрию.

**CLI-команды:**
```bash
python main.py request-access --service-id protected-service-1
python main.py revoke-local --jti <JTI>
```

#### 4. Серверный агент (PEP на стороне сервиса)

**Расположение:** data plane, конечная точка защищаемого сервиса.

**Функции:**
- Приём управляющих команд от контроллера (`/activate`, `/revoke`).
- Валидация билета перед активацией.
- Управление peer-записями TUN-шифратора (добавление / удаление).
- Автономная очистка peer-состояния по истечению `exp`.
- Фоновая синхронизация списка отозванных `jti` с контроллером.

**Важно:** серверный агент не проксирует трафик. Он лишь временно открывает ровно тот канал, который соответствует разрешённой сессии.

#### 5. Подсистема телеметрии

**Роль:** централизованный сбор событий от всех узлов.

**События жизненного цикла:**
- `request` — запрос доступа.
- `auth_done` — аутентификация завершена.
- `policy_done` — решение политики принято.
- `ticket_issued` — билет выдан.
- `peer_add` — peer добавлен.
- `tunnel_up` — туннель установлен.
- `first_data` — первый прикладной пакет.
- `revoke_cmd` — команда отзыва отправлена.
- `traffic_stop` — трафик прекращён.

По этим событиям вычисляются ключевые метрики эксперимента:
- `T_setup = t_first_data − t_request`
- `T_revoke = t_traffic_stop − t_revoke_cmd`
- `K_avg` — среднее число одновременно активных сессий.

### Сетевая топология стенда

Docker Compose создаёт две изолированные сети:

- **`control-plane` (172.20.0.0/24)** — связь контроллера, IdP, агентов, телеметрии.
- **`data-plane` (172.21.0.0/24)** — прямые линки между клиентским агентом и защищаемым сервисом.

Агенты (client-agent, server-agent) подключены к обеим сетям и имеют capability `NET_ADMIN` для управления TUN-интерфейсами.

---

## Структура проекта

```
prototype/
├── docker-compose.yml          # Топология стенда
├── Makefile                    # Утилиты: build, up, down, test
├── requirements.txt            # Python-зависимости
│
├── common/                     # Общие модули
│   ├── models.py               # Дата-классы: AccessTicket, TransportProfile, MetricEvent
│   ├── crypto.py               # Ed25519: generate, sign, verify, canonical_encode
│   ├── telemetry.py            # TelemetryCollector + HTTP-отправка
│   └── config.py               # Загрузка конфигурации из env
│
├── controller/                 # Центральный PDP
│   ├── main.py                 # FastAPI: /access, /revoke, /revoked
│   ├── auth.py                 # Клиент для Mock IdP
│   ├── policy_engine.py        # Rule-based policy-check
│   └── config/registry.json    # Реестр сервисов и агентов
│
├── client_agent/               # Клиентский PEP
│   ├── main.py                 # CLI
│   ├── ticket_manager.py       # Локальная валидация билета
│   ├── tunnel.py               # TUN-шифратор клиента (AES-256-GCM)
│   ├── key_store.py            # Загрузка PSK
│   ├── controller_client.py    # HTTP-клиент контроллера
│   ├── idp_client.py           # HTTP-клиент IdP
│   └── revoked_cache.py        # Кэш отозванных jti
│
├── server_agent/               # Серверный PEP
│   ├── main.py                 # FastAPI: /activate, /revoke
│   ├── ticket_validator.py     # Валидация билета
│   ├── tunnel.py               # TUN-шифратор сервера (AES-256-GCM)
│   ├── session_monitor.py      # Автоочистка по exp
│   ├── key_store.py            # Загрузка PSK
│   └── revoked_cache.py        # Синхронизация Revoked
│
├── mock_idp/                   # Упрощённый IdP
│   ├── main.py                 # FastAPI: /auth
│   └── users.json              # Статические учётные записи
│
├── protected_service/          # Целевой сервис для прогонов
│   └── main.py                 # FastAPI: /, /api/data, /health
│
├── telemetry_server/           # Сбор событий
│   └── main.py                 # FastAPI: /event, /report, /clear
│
├── scripts/
│   └── init_keys.py            # Генерация ключей (Ed25519, PSK, WG)
│
├── keys/                       # Ключевой материал (для тестового стенда)
│   ├── controller.sk / .pk     # Ed25519 контроллера
│   ├── client_keys.json        # PSK клиента
│   ├── server_keys.json        # PSK сервера
│   └── server_wg.json          # TUN-ключи сервера
│
├── tests/
│   ├── unit/                   # Юнит-тесты (crypto, models, telemetry)
│   ├── integration/            # E2E-тесты (сквозной сценарий)
│   └── security/               # Негативные тесты (N1–N7)
│
├── stands/                     # Сравнительные стенды (Direct-ZTNA, Gateway-ZTNA, VPN)
│   ├── direct/                 # Стенд Direct-ZTNA (1×3)
│   ├── gateway/                # Стенд Gateway-ZTNA (1×3)
│   ├── vpn/                    # Стенд VPN (1×3)
│   └── run_benchmarks.py       # Автоматический запуск benchmark на всех стендах
│
└── docs/
    ├── architecture.md         # Подробное описание архитектуры
    └── experiment_compliance.md # Соответствие стендов требованиям главы 5
```

---

## Требования

### Системные
- Linux с поддержкой Docker и TUN-интерфейсов.
- Пользователь должен быть в группе `docker` (или использовать `sg docker -c "..."`).

### Установленные инструменты
- `docker` ≥ 20.10
- `docker-compose` ≥ 2.20 (или `docker compose` plugin)
- `python` ≥ 3.11 (для локального запуска тестов)
- `curl` (для ручных проверок)

### Если Docker Compose не установлен
```bash
sudo curl -L "https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

---

## Быстрый старт

### 1. Клонирование и переход в директорию

```bash
cd prototype/
```

### 2. Генерация ключей (если директория `keys/` пуста)

```bash
python3 scripts/init_keys.py
```

Скрипт создаёт:
- пару Ed25519 для контроллера (`controller.sk`, `controller.pk`);
- PSK для пары «alice — protected-service-1» (`client_keys.json`, `server_keys.json`);
- TUN-ключи сервера (`server_wg.json`).

### 3. Сборка и запуск стенда

```bash
sg docker -c "docker-compose build"
sg docker -c "docker-compose up -d"
```

Или через Makefile:
```bash
sg docker -c "make build"
sg docker -c "make up"
```

### 4. Проверка состояния сервисов

```bash
curl http://localhost:8080/health   # controller
curl http://localhost:8081/health   # mock-idp
curl http://localhost:8082/health   # telemetry
curl http://localhost:8090/health   # protected-service
```

### 5. Запрос доступа (ручная проверка)

```bash
sg docker -c "docker-compose exec -T client-agent python main.py request-access --service-id protected-service-1"
```

Ожидаемый вывод:
```
[client] Authenticated as alice
[client] Ticket received: alice-protected-service-1-<timestamp>-<random>
[client] Ticket signature valid
[client] Access granted. Tunnel active for service protected-service-1
[client] Ticket expires at <exp> (in 300 seconds)
```

### 6. Просмотр телеметрии

```bash
curl -s http://localhost:8082/report | python3 -m json.tool
```

### 7. Отзыв доступа

```bash
curl -X POST http://localhost:8080/revoke \
  -H "Content-Type: application/json" \
  -d '{"jti": "<JTI_из_шага_5>"}'
```

### 8. Остановка стенда

```bash
sg docker -c "docker-compose down -v"
# или
sg docker -c "make down"
```

---

## Описание работы прототипа

### Жизненный цикл доступа (успешный сценарий)

```
┌────────┐   1. request-access    ┌─────────────┐
│ Client │ ─────────────────────► │ Controller  │
│ Agent  │                        │   (PDP)     │
└────────┘                        └──────┬──────┘
     ▲                                   │
     │                                   │ 2. auth via IdP
     │                                   │ 3. policy-check
     │                                   │ 4. sign ticket
     │                                   │ 5. POST /activate to server
     │                                   │
     │ 6. return ticket                  ▼
     │ ◄──────────────────────────┌─────────────┐
     │                            │ Server Agent│
     │                            │  (add peer) │
     │                            └─────────────┘
     │
     │ 7. validate ticket locally
     │ 8. check PSK in key_store
     │ 9. add_peer (activate tunnel)
     ▼
┌────────┐   10. direct traffic    ┌─────────────┐
│ Client │ ◄═════════════════════► │   Server    │
│ Agent  │    TUN-туннель (AES-256-GCM)  │   Agent     │
└────────┘                         └─────────────┘
```

**Пояснение шагов:**

1. **Запрос.** Клиентский агент отправляет `POST /access` с `user_token` и `service_id`.
2. **Аутентификация.** Контроллер обращается к Mock IdP и получает `sub` и `attrs`.
3. **Policy-check.** Проверяется, существует ли сервис в реестре и разрешён ли доступ пользователю.
4. **Формирование билета.** Контроллер создаёт `AccessTicket` с `jti`, временным окном `nbf`–`exp`, транспортным профилем и `key_id`.
5. **Подпись.** Payload билета сериализуется каноническим образом (`sort_keys=True, separators=(',', ':')`) и подписывается закрытым ключом Ed25519 контроллера.
6. **Уведомление сервера.** Контроллер отправляет серверному агенту команду `/activate` с копией билета.
7. **Возврат билета клиенту.** Клиент получает подписанный билет.
8. **Локальная валидация.** Клиентский агент проверяет:
   - подпись открытым ключом контроллера;
   - `aud == "client"`;
   - `nbf <= now <= exp`;
   - `jti` не в локальном списке отозванных.
9. **Проверка PSK.** По `key_id` извлекается предварительно распределённый ключ.
10. **Активация туннеля.** Выполняется `add_peer` с параметрами из `transport` и PSK. TUN-интерфейс поднимается.
11. **Прямое соединение.** Прикладной трафик идёт напрямую между клиентом и сервером через TUN-шифратор, минуя контроллер.

### Жизненный цикл отзыва доступа

1. Администратор (или автоматика) вызывает `POST /revoke` на контроллере с `jti`.
2. Контроллер добавляет `jti` в множество `Revoked`.
3. Контроллер отправляет `POST /revoke` серверному агенту.
4. Серверный агент удаляет peer-состояние (`remove_peer`).
5. Клиентский агент при следующей синхронизации (или по локальному revoke) деактивирует туннель.

### Модель безопасности: два фактора доступа

Для установления соединения необходимо **одновременно**:

1. **Билет** — подписанное криптографическое разрешение контроллера, содержащее `service_id`, `scope`, `exp`.
2. **PSK** — предварительно распределённый симметричный ключ, привязанный к конкретной паре «клиент–сервис».

**Свойства:**
- Компрометация только билета (без PSK) — недостаточно для соединения.
- Компрометация только PSK (без валидного подписанного билета) — недостаточно: параметры `endpoint`, `scope`, `exp` содержатся только в билете, а подделка невозможна без закрытого ключа контроллера.
- Это реализует принцип **separation of duties** на уровне архитектуры доступа.

### Криптографическое молчание (silent drop)

Если к серверному агенту приходит пакет без корректного ключевого материала, TUN-шифратор отбрасывает его без отправки ответа. С точки зрения сканирующего хоста сервис **невидим** до выдачи билета и после его отзыва. Это подтверждается экспериментально.

---

## Тестирование

### Запуск всех тестов

```bash
cd prototype/
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Все тесты
PYTHONPATH=$(pwd) pytest tests/ -v

# Только unit
PYTHONPATH=$(pwd) pytest tests/unit -v

# Только интеграционные (требует запущенного стенда)
sg docker -c "docker-compose up -d"
PYTHONPATH=$(pwd) pytest tests/integration -v

# Только security (требует запущенного стенда)
PYTHONPATH=$(pwd) pytest tests/security -v
```

### Структура тестов

#### Unit-тесты (`tests/unit/`)

| Тест | Что проверяет |
|------|---------------|
| `test_crypto.py` | Генерация ключей, подпись/проверка, детекция подделки payload, неверный ключ, невалидный hex |
| `test_models.py` | Roundtrip сериализации для TransportProfile, AccessTicket, RevokeCommand, MetricEvent |
| `test_telemetry.py` | emit, filter по node/event/ticket_id, clear, глобальный коллектор |

**Результат:** 14/14 ✅

#### Интеграционные тесты (`tests/integration/test_e2e.py`)

| Тест | Сценарий |
|------|----------|
| `test_health_endpoints` | Все сервисы (controller, IdP, telemetry, protected-service) отвечают на /health |
| `test_access_request_success` | Запрос доступа возвращает валидный подписанный билет со всеми полями |
| `test_server_agent_activate_and_revoke` | После выдачи билета сервер активирует peer; после revoke — удаляет. Проверка по телеметрии |
| `test_revoke_prevents_reuse` | Отозванный jti появляется в списке /revoked |
| `test_access_denied_unknown_service` | Доступ к несуществующему сервису возвращает 403 |
| `test_access_denied_invalid_token` | Невалидный токен возвращает 401 |

**Результат:** 6/6 ✅

#### Негативные тесты безопасности (`tests/security/test_negative.py`)

| ID | Тест | Проверяемое свойство |
|----|------|----------------------|
| N1 | `test_access_without_ticket_denied` | Попытка активации с фальшивым билетом (невалидная подпись) отклоняется |
| N2 | `test_wrong_audience_rejected` | Билет с `aud="server"` отклоняется клиентским агентом |
| N3 | `test_missing_psk_rejected` | Отсутствие PSK для `key_id` блокирует активацию |
| N4 | `test_expired_ticket_rejected` | Просроченный билет (`exp` в прошлом) отклоняется |
| N5 | `test_revoked_jti_rejected` | Повторное использование отозванного `jti` невозможно |
| N6 | `test_horizontal_movement_blocked` | PSK для S2 отсутствует — горизонтальное перемещение невозможно |
| N7 | `test_scope_enforcement` | Подмена `scope` в билете ломает подпись — доступ блокируется |

**Результат:** 7/7 ✅

### Проверка через телеметрию

После прогона тестов можно проверить события:

```bash
curl -s http://localhost:8082/report | python3 -m json.tool
```

Ожидаемые события для успешного сценария:
- `client` → `request`
- `controller` → `auth_done`, `policy_done`, `ticket_issued`
- `server` → `peer_add`
- `client` → `tunnel_up`, `first_data`

---

## Сравнительные стенды

Для экспериментального сравнения архитектур в директории `stands/` созданы три изолированных Docker-стенда с тремя защищаемыми сервисами (S1, S2, S3):

| Стенд | Расположение | Архитектура | Сети |
|-------|-------------|-------------|------|
| Direct-ZTNA | `stands/direct/` | Прямые TUN (/32) с AES-256-GCM | control-plane 172.22.0.0/24, data-plane 172.23.0.0/24 |
| Gateway-ZTNA | `stands/gateway/` | FastAPI reverse proxy + TLS | control-plane 172.26.0.0/24, data-plane 172.27.0.0/24 |
| VPN | `stands/vpn/` | OpenVPN L3-туннель | control-plane 172.24.0.0/24, data-plane 172.25.0.0/24 |

### Эксперимент экспонированности (exposure)

Каждый стенд включает скрипт `exposure_experiment.py`, который проверяет:
1. **Внешняя видимость** — ping, TCP-connect, HTTP к S1/S2/S3 до доступа, во время сессии и после отзыва.
2. **Lateral movement** — доступ из инфраструктурного компонента (`gateway-ztna`, `vpn-server`, `direct-controller`) к сервисам.

```bash
cd stands/gateway
sg docker -c "docker-compose up -d"
python3 exposure_experiment.py
sg docker -c "docker-compose down"
```

Аналогично для `stands/vpn/` и `stands/direct/`.

### Результаты exposure

| Стенд | До доступа | Во время сессии | После отзыва | Lateral movement |
|-------|-----------|-----------------|--------------|------------------|
| **Gateway-ZTNA** | 0 сервисов (HTTP 401) | 1 сервис (S1=200, S2/S3=403) | 0 сервисов (401) | **3/3** из шлюза (plain HTTP) |
| **VPN** | 0 сервисов | 3 сервиса (200) | 0 сервисов | **3/3** из VPN-сервера (L3) |
| **Direct-ZTNA** | 0 сервисов (silent drop) | 1 сервис (S1=200, S2/S3=000) | 0 сервисов | **0/3** из контроллера (нет PSK/TUN) |

### Benchmark (временные характеристики)

```bash
cd stands/<mode>
sg docker -c "docker-compose up -d"
python3 experiment.py        # 10 прогонов
sg docker -c "docker-compose down"
```

Или запуск всех трёх стендов:

```bash
python3 stands/run_benchmarks.py
```

---

## Troubleshooting

### `permission denied while trying to connect to docker API`

Пользователь не в группе `docker`:
```bash
sudo usermod -aG docker $USER
# Перелогиниться или:
sg docker -c "docker-compose ..."
```

### `ModuleNotFoundError: No module named 'common'`

В Dockerfile не задан `PYTHONPATH`. Проверьте наличие строки:
```dockerfile
ENV PYTHONPATH=/app
```

### `Controller private key not found at /app/keys/controller.sk`

Ключи не смонтированы в контейнер. Проверьте `docker-compose.yml`:
```yaml
volumes:
  - ./keys:/app/keys:ro
```

### `No PSK for key_id ...`

Несоответствие `key_id` в `registry.json` / билете и имени ключа в `client_keys.json` / `server_keys.json`. Проверьте, что `init_keys.py` сгенерировал ключи с правильными именами.

### TUN-интерфейс не работает в контейнере

Убедитесь, что в `docker-compose.yml` заданы:
```yaml
cap_add:
  - NET_ADMIN
  - SYS_MODULE
sysctls:
  - net.ipv4.conf.all.src_valid_mark=1
```

---

## Лицензия и ограничения

Это **экспериментальный прототип** для исследовательских целей. Он не предназначен для промышленного развёртывания.

**Известные ограничения:**
- Ключи хранятся в файлах (soft-token), без HSM/TPM.
- Mock IdP не реализует MFA, федерацию, непрерывную оценку контекста.
- Управление жизненным циклом ключей (ротация, отзыв PSK) не реализовано.
- Нет механизма обхода NAT/STUN/TURN для клиентов за symmetric NAT.
- L7-инспекция и application-aware проксирование вне scope прототипа.

---

## Ссылки

- [План реализации](../План_реализации_прототипа.md)
- [STATUS.md](../STATUS.md) — текущий прогресс реализации
- [docs/architecture.md](docs/architecture.md) — подробное архитектурное описание
