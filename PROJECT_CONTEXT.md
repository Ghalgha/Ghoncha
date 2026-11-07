# Ghoncha — PROJECT_CONTEXT

> **Назначение:** единый актуальный контекст проекта для разработчиков и AI-агентов. Этот файл определяет цель, архитектурные границы, подтверждённое состояние реализации, порядок дальнейшей работы и обязательные инженерные правила.
>
> **Актуальность:** 2026-11-07  
> **Текущий HEAD main:** `ddcda99f6b77f254dd54641b4e6ffa39ab84d35d` (последний context-only commit; добавлены полевые наблюдения и обновлён статус CI/PR; код проекта не менялся)  
> **Основная ветка на момент переноса:** `main`, HEAD до этого коммита `f7140b2f275534dff1b09927110e0ae30bb9ad3e`  
> **Расположение документа:** `main:/PROJECT_CONTEXT.md`

Статусы в этом документе:
- **[РЕАЛИЗОВАНО]** — код находится в `main` и доступен после обычного checkout основной ветки.
- **[РЕАЛИЗОВАНО В PR]** — код находится в указанной незамёрженной рабочей ветке; это ещё не часть `main`.
- **[ЧАСТИЧНО]** — существует часть механизма, но он не интегрирован в полный пользовательский сценарий.
- **[В РАБОТЕ]** — следующий или текущий ограниченный этап реализации.
- **[НЕ РЕАЛИЗОВАНО]** — требования зафиксированы, но рабочего кода пока нет.
- **[ТРЕБУЕТ РЕШЕНИЯ]** — нельзя считать архитектурно утверждённым до отдельного обоснования и проверки.

Статус реализации всегда относится к конкретной ветке и проверенному commit SHA. Наличие кода в открытом PR не означает, что функциональность доступна в `main` или готова для пользователей.

---

## 1. Цель продукта

Ghoncha — кроссплатформенный VPN. Его основной сетевой путь должен использовать VK Calls TURN как транспорт для передачи VPN-трафика между клиентом Ghoncha и собственным VPN-шлюзом пользователя/сервиса.

VK Calls — это **транспортная среда**, а не назначение приложения. Продукт не является приложением для голосовых или видеозвонков и не должен смещать архитектуру в сторону управления звонками как конечной функции.

Основная задача VPN:
1. Перехватывать IP-трафик устройства через системный VPN-интерфейс.
2. Защищать его стандартным криптографическим VPN-протоколом.
3. Передавать защищённые записи через выбранный транспорт; основной вариант — VK Calls TURN.
4. Доставлять записи на собственный Ghoncha Gateway.
5. Проверять подлинность, расшифровывать VPN-трафик и маршрутизировать IP-пакеты.
6. Возвращать ответы тем же логическим путём.
7. Обеспечивать безопасное переключение сетей, восстановление соединения и управление собственным сервером.

Продукт должен иметь собственную архитектуру, собственные интерфейсы, модель состояния, систему конфигурации, серверную часть и пользовательский опыт. Нельзя копировать структуру, код, UX или ограничения какого-либо существующего приложения. Внешние реализации допустимо изучать только как технические источники для проверки протокольной совместимости; они не являются спецификацией Ghoncha.

## 2. Принципы проекта

1. **VK Calls TURN — основной транспорт**, но не единственно допустимый.
2. **Транспорты взаимозаменяемы.** Новый транспорт подключается через общий контракт и не требует переписывания IP-обработки, VPN-криптографии, маршрутизации или UI.
3. **Rust Core переносим.** Он не должен зависеть от Android API, VK SDK, конкретного устройства или одного сетевого транспорта.
4. **Безопасность прежде обходных оптимизаций.** Нельзя отключать проверку сертификатов, аутентификацию, replay protection, шифрование или проверки целостности ради совместимости, скорости или расхода батареи.
5. **Измерения вместо предположений.** Скорость, задержка, расход батареи, доступность транспорта и устойчивость подтверждаются тестами.
6. **Никаких обещаний гарантированного обхода блокировок.** Наличие VK Calls или TURN в сети не гарантирует доступность всех необходимых адресов, портов и протоколов.
7. **Ограниченные ресурсы.** Очереди, буферы, повторы, таймеры, число потоков и сетевых сессий имеют явные пределы.
8. **Последовательная реализация.** Сначала закрывается текущий этап и его критерии готовности; переходить к следующему этапу можно после тестов и проверки зависимостей.
9. **Документация является частью реализации.** Изменение архитектуры, поведения или статуса кода отражается в документации в том же этапе.
10. **Не выдавать прототип за готовый продукт.** Сборка, unit-тест, интеграционный тест и проверка на реальном устройстве — разные уровни подтверждения.

## 3. Целевая архитектура

### 3.1. Компоненты

- **Platform Adapter** — системный VPN lifecycle, TUN, разрешения, состояние сети, системные callback-и и платформенные сокеты.
- **Rust Core** — единая переносимая логика VPN, управление состоянием, IP-пакетами, сессиями, маршрутами, политиками и статистикой.
- **Packet Engine** — ограниченный и проверяемый разбор IPv4/IPv6, классификация потоков и передача пакетов между TUN и VPN-протоколом.
- **Tunnel Engine** — криптографически защищённый VPN-туннель и управление peer-сессиями.
- **Transport API** — общий контракт передачи полных непрозрачных записей.
- **Transport Adapters** — реализации VK Calls TURN, generic TURN и будущих транспортов.
- **Credential Providers** — отдельные компоненты получения и обновления краткоживущих учётных данных. Получение credentials не должно выполняться в packet hot path.
- **Ghoncha Gateway** — серверное завершение VPN-туннеля, маршрутизация, NAT/forwarding и применение политик.
- **Server Control Plane** — настройка шлюза, управление пользователями/peer-ами, ключами, адресами, лимитами, версиями и состоянием сервера.
- **Management/Deployment** — безопасное развёртывание и обслуживание собственного сервера из приложения.

### 3.2. Логический путь пакета

```text
Device application
  -> OS VPN interface / TUN
  -> Rust Packet Engine
  -> VPN Tunnel Engine
  -> Transport API (complete opaque records)
  -> Selected Transport Adapter
       -> VK Calls credential provider (setup/refresh only)
       -> TURN client
       -> DTLS-SRTP / RTP-SRTP carrier for the VK path
       -> VK Calls TURN relay
  -> Ghoncha Gateway UDP endpoint
  -> SRTP verification/deprotection on the VK path
  -> VPN Tunnel Engine
  -> IP forwarding / NAT / policy
  -> destination network
```

Ответный трафик проходит обратный путь. TURN relay — только ретранслятор; он не является VPN Gateway и не должен получать ключи внутреннего VPN-туннеля.

### 3.3. Разделение уровней безопасности

На основном VK-пути должны быть независимо реализованы и проверены:
- краткоживущие TURN credentials и аутентификация TURN allocation;
- проверка подлинности Ghoncha Gateway;
- DTLS-SRTP handshake и согласование допустимого SRTP-профиля;
- SRTP integrity, шифрование и replay protection;
- внутренняя VPN-аутентификация и защита IP-трафика.

TURN username/password, VK call link/hash, DTLS identity, SRTP keys и VPN peer keys — разные секреты с разными сроками действия и назначением. Нельзя смешивать их в одну общую модель credentials.

После согласования DTLS-SRTP VPN datagram переносится в RTP payload и защищается SRTP. Не следует отправлять DTLS application-data records через ассоциацию, согласовавшую профиль DTLS-SRTP. Конкретные параметры должны соответствовать RFC 5764 и согласованному SRTP-профилю.

## 4. VPN-протокол и WireGuard

**[ТРЕБУЕТ РЕШЕНИЯ]** WireGuard рассматривается как основной кандидат на внутренний VPN-протокол Ghoncha. Это не транспорт VK Calls и не замена TURN.

Ожидаемая роль внутреннего VPN-протокола:
- peer identity и криптографическая аутентификация;
- согласование ключей;
- шифрование и целостность IP-трафика;
- защита от повторного воспроизведения;
- стандартизованный формат VPN datagram.

Требования:
1. Не разрабатывать собственный криптографический handshake, KDF, AEAD или replay protocol.
2. До выбора Rust-движка провести аудит лицензии, поддержки платформ, состояния безопасности, совместимости с официальной реализацией, fuzzing-результатов и производительности.
3. Проверить interoperability с независимыми реализациями.
4. Для Linux Gateway оценить зрелую системную реализацию как baseline; userspace-вариант допустим после сравнимых проверок.
5. Не заявлять WireGuard реализованным: на проверенном HEAD его рабочая интеграция отсутствует.
6. Зафиксировать отдельное архитектурное решение (ADR) до добавления tunnel engine и закрепления зависимости.

## 5. VK Calls: credentials и транспорт

VK Calls должен использоваться как основной источник/среда TURN-доступа. Поддерживаются два полноценных сценария получения данных подключения.

### 5.1. Ручной сценарий

**[НЕ РЕАЛИЗОВАНО]**
- Пользователь вручную вводит или импортирует call link/hash.
- Приложение валидирует формат и извлекает только необходимые параметры.
- Секретные части хранятся безопасно и не попадают в логи, crash reports или аналитику.
- Пользователь может просматривать, обновлять, удалять и выбирать сохранённые записи.
- Истёкшие или отозванные данные не должны автоматически использоваться повторно.

### 5.2. Автоматический сценарий

**[НЕ РЕАЛИЗОВАНО]**
- Пользователь явно авторизует VK-сессию.
- Приложение получает разрешённый доступ к созданию/присоединению к звонку и получению TURN-параметров.
- Создание/присоединение к звонку и обновление credentials выполняются только по явному пользовательскому намерению и в рамках разрешённого API/сценария.
- При завершении звонка, logout, отзыве разрешения или смене сессии связанные credentials инвалидируются.
- Нельзя полагаться на неофициальный или нестабильный формат ответа без отдельного теста и обработки изменений.
- Автоматическое обновление должно быть ограничено сроком жизни сессии и политикой повторов; запрещены бесконечные фоновые циклы создания звонков.

### 5.3. TURN и carrier

- Основной режим — TURN over UDP.
- TURN over TCP/TLS рассматривается как fallback при подтверждённой необходимости и поддержке конкретного endpoint.
- TURN TCP/TLS fallback сохраняет datagram semantics на уровне TURN, но имеет head-of-line blocking и не должен автоматически считаться равноценным UDP по задержке.
- Generic TURN engine не равен готовому VK adapter.
- Для VK-пути остаются отдельные задачи: credential provider, совместимость с реальным VK relay, DTLS-SRTP, RTP/SRTP, Gateway interop, таймеры и восстановление сессии.
- TURN allocation, permission, channel binding, DTLS association, SRTP context и VPN tunnel — независимые состояния.

## 6. Транспортная абстракция

Общий интерфейс должен передавать полные непрозрачные записи VPN-туннеля. Он не должен знать про VK API, call links, TURN username, RTP, SRTP, внутренние IP-пакеты или Android Network.

Обязательные свойства:
- одна успешная отправка принимает одну полную запись либо явно сообщает backpressure;
- приём возвращает полные записи, а не неопределённые фрагменты;
- явные максимальные размеры и ограничения очередей;
- отмена и закрытие идемпотентны;
- ошибки и события привязаны к session/network generation;
- capability описывает адресные семейства, datagram/stream semantics, reliability, MTU, migration, keepalive и ограничения;
- выбор транспорта выполняется после проверки endpoint, peer identity и ограниченного health probe;
- смена транспорта не должна менять внутренний VPN peer identity;
- старый путь закрывается после успешной аутентифицированной миграции и завершения drain.

Планируемые адаптеры:
- VK Calls TURN — основной;
- generic TURN — отдельный, независимый от VK provider;
- direct UDP — будущий, если соответствует threat model;
- MASQUE CONNECT-UDP/CONNECT-IP — кандидаты, требующие отдельного boundary design;
- другие транспорты — только через тот же контракт и после security/interoperability review.

## 7. Три профиля производительности

В пользовательском приложении должны быть ровно три основных режима. Режим выбирает политику масштабирования независимых транспортных потоков, а не число OS threads, TURN Channels или TURN allocations по умолчанию.

### Unlimited
- Нет произвольного пользовательского потолка на полезную пропускную способность.
- Начинать с малого количества потоков и постепенно увеличивать параллелизм.
- Продолжать увеличение только пока измеряемый marginal goodput оправдывает дополнительные ресурсы.
- Остановиться или уменьшить число потоков при ухудшении RTT, потерь, очередей, CPU, температуры, лимитов сервера или стабильности.
- «Без ограничений» не означает бесконечное потребление ресурсов и не отменяет серверные safety limits.

### Standard
- Целевой диапазон — 30–40 независимых data flows, предпочтительная точка — 35, если транспорт и сервер реально поддерживают такое количество.
- Запускать потоки постепенно, без burst-подключения.
- Если адаптер поддерживает меньше потоков, показывать фактический лимит, а не имитировать нужное число логическими каналами.
- Поддерживать live resize и безопасный drain, где это возможно.

### EnergySaving
- Начинать с одного потока.
- Увеличивать число потоков только при подтверждённой нагрузке, росте очереди или недостаточном goodput.
- После снижения нагрузки безопасно удалять избыточные потоки.
- Использовать batching, буферные пулы, event-driven I/O, таймеры по реальным deadline и ограниченные retry.
- Не отключать keepalive/refresh, аутентификацию, шифрование или replay protection ради экономии.

### Общие правила профилей
- Переключение во время VPN-сессии должно быть live reconfiguration без пересоздания TUN и без смены peer identity.
- Команды имеют revision/generation, чтобы поздний асинхронный ответ не отменял более новый выбор пользователя.
- Нельзя применять новый профиль как активный, пока runtime фактически не достиг его допустимого состояния.
- Показывать запрошенный профиль, фактическое число потоков и причину ограничения.
- Сравнение режимов speed test должно запускаться пользователем, идти последовательно и измерять сопоставимые условия. Не следует одновременно запускать тесты трёх режимов.
- Короткий speed test не является измерением энергопотребления. Battery claims требуют длительного device-side тестирования.

**Состояние:** [ЧАСТИЧНО] В `crates/transport-api/src/profiles.rs` реализованы типы трёх профилей, планирование числа независимых потоков, policy scaling, revision selection и рекомендации следующего шага по измерениям. Полный runtime controller, live orchestration, UI, speed test и device power measurement ещё не завершены. Эта логика присутствует в main; она не должна трактоваться как готовая пользовательская функция.

## 8. Энергоэффективность и производительность

Приоритет — минимальный дополнительный расход энергии при сохранении безопасности, доступности и полезной пропускной способности.

Обязательные инженерные решения:
- пакетный data path остаётся в Rust;
- никаких JNI/FFI вызовов на каждый IP-пакет или tunnel record;
- event-driven readiness вместо постоянного polling;
- bounded queues и reusable buffers;
- batching syscall-ов и событий с явными budget;
- никаких thread/task-per-packet;
- отсутствие ненужных копирований и heap allocations в hot path;
- отдельные таймеры для TURN allocation, permission, channel, NAT mapping и DTLS retransmission;
- отсутствие keepalive, если реальный пользовательский трафик уже поддерживает mapping;
- Android network callbacks вместо polling состояния сети;
- никаких wake locks на период retry/idle;
- измерение CPU, memory, thermal throttling, radio activity, RTT, jitter, loss, goodput и battery drain.

Тестирование производительности обязательно отдельно для Wi-Fi/cellular, screen-on/screen-off, idle/active traffic, IPv4/IPv6 и network handover. Не публиковать обещания автономности или скорости без повторяемых измерений на физических устройствах.

## 9. Белые списки и ограниченные сети

Поддержка работы в сетях с ограниченным списком доступных сервисов — важное требование, но не гарантия.

Правила:
- тестировать только реально наблюдаемые адреса, порты, протоколы и направления;
- различать DNS failure, timeout, TCP connect failure, TLS validation failure, TURN auth failure и peer handshake failure;
- не делать вывод о блокировке по одному timeout;
- не считать успешный доступ к VK доказательством доступности Ghoncha Gateway;
- не использовать hostname/port как единственное основание выбора транспорта;
- не заявлять «обход гарантирован» без тестов на конкретной сети и конфигурации;
- fallback допускается только на заранее настроенный и проверенный транспорт, а не на произвольный endpoint;
- диагностика должна объяснять фактический слой сбоя без необоснованных утверждений о DPI/цензуре.

## 10. Android: системная интеграция

Android — первая целевая платформа.

Обязательные компоненты:
1. `VpnService` lifecycle, user consent, foreground service и корректное закрытие.
2. Создание TUN, явная передача владения FD в Rust и отсутствие double-close/leak.
3. `ConnectivityManager.NetworkCallback` и monotonic network generation.
4. DNS resolution через выбранный `Network`.
5. Для каждого внешнего transport socket: `VpnService.protect()` до первого send и bind к выбранной `Network`, если требуется.
6. Проверка generation до и после подготовки сокета.
7. Native reactor, обслуживающий readiness и protocol timers.
8. Чёткая отмена/очистка при disconnect, permission revoke, process stop и handover.
9. Device tests на Wi-Fi и cellular, IPv4/IPv6, повторное подключение и отсутствие утечек FD/Allocation.

Нельзя считать подготовленный UDP socket готовым VPN-туннелем. Состояния «сокет создан», «TURN allocation готов», «DTLS-SRTP authenticated», «VPN peer authenticated» и «полезный IP-трафик проходит» должны быть раздельными.

## 11. Переносимость и целевые платформы

Rust Core должен оставаться платформенно-нейтральным и не включать платформенные API в общие crate.

Целевые клиенты:
- Android — первая реализация;
- iOS — будущая реализация через системный Network Extension/VPN lifecycle;
- Windows — будущая реализация с платформенным TUN/Wintun boundary;
- Linux — будущая реализация с TUN и системной маршрутизацией;
- OpenWrt/роутеры — будущая реализация с минимальными runtime/resource requirements.

Для каждой платформы нужен тонкий Platform Adapter, который реализует TUN, socket protection/binding, lifecycle и event delivery. Общие packet/tunnel/transport/state-machine crates не должны зависеть от Android, iOS, Windows, Linux или OpenWrt SDK.

Портирование начинается после стабилизации соответствующих публичных Rust contracts и тестов. Не добавлять пустые платформенные заглушки ради формального заявления о поддержке.

## 12. Собственный сервер и развёртывание

Ghoncha должен предоставлять собственный Gateway и возможность развёрнуть его на VPS непосредственно из приложения.

### Функции управления
- подключение к VPS по SSH с явным подтверждением пользователя;
- проверка совместимости ОС, архитектуры, прав и свободных ресурсов;
- установка/обновление Gateway и его зависимостей;
- безопасная передача конфигурации и ключей;
- настройка firewall, портов, маршрутов и forwarding;
- запуск, остановка, перезапуск и проверка состояния;
- просмотр ограниченных диагностических логов и метрик;
- обновление версии с проверкой целостности артефактов;
- резервное копирование конфигурации и безопасный rollback;
- удаление установки по подтверждению пользователя.

### Безопасность
- SSH host key verification обязательна; нельзя автоматически принимать неизвестный host key.
- Приватные ключи и пароли не логируются и не передаются в открытом виде.
- Предпочитать ограниченную отдельную учётную запись и минимальные привилегии.
- Команды деплоя должны быть детерминированными, версионированными и идемпотентными.
- Нельзя считать сервер готовым только потому, что SSH-команда завершилась успешно.
- После deploy выполняются health checks: процесс, сокеты, firewall, peer config и end-to-end tunnel test.
- Control Plane и packet forwarding должны быть разделены; управление сервером не должно блокировать data plane.

**Состояние:** [НЕ РЕАЛИЗОВАНО] На проверенном HEAD нет Ghoncha Gateway, SSH deploy workflow, server manager или полноценного server control plane.

## 13. UI и пользовательские функции

Планируемый пользовательский сценарий:
- подключение/отключение VPN;
- выбор трёх профилей производительности;
- ручное добавление/импорт VK call link/hash;
- автоматическая авторизация VK и получение параметров сессии;
- выбор/настройка Ghoncha Gateway;
- создание и управление собственным сервером;
- диагностика текущего транспорта, состояния туннеля и причины ошибки;
- статистика трафика, задержки, потерь и фактического числа flows;
- сравнение профилей через пользовательский speed test;
- безопасное управление credentials, peer keys и SSH access.

UI не должен содержать протокольную логику, retry loops, обработку пакетов или хранение долгоживущих секретов в открытом виде.

## 14. Подтверждённое состояние кода

### 14.1. Основная ветка `main`

Следующее подтверждено в `main` на commit `f7140b2f275534dff1b09927110e0ae30bb9ad3e`.

- **[РЕАЛИЗОВАНО]** Rust workspace и базовая структура crates.
- **[РЕАЛИЗОВАНО]** Packet crate с базовым разбором/представлением IPv4/IPv6 и flow metadata. Это не полноценный firewall, routing policy или исчерпывающий RFC validator.
- **[РЕАЛИЗОВАНО]** Flow dispatcher и базовая allocation policy.
- **[РЕАЛИЗОВАНО]** Transport API: credentials/identity/keepalive/profile/RTP-related types and contracts. Наличие типов не означает наличие end-to-end runtime.
- **[РЕАЛИЗОВАНО]** TURN UDP Sans-I/O protocol wrapper, caller-driven timers/events и caller-owned buffers.
- **[РЕАЛИЗОВАНО]** TURN TCP client-side stream driver и framing.
- **[РЕАЛИЗОВАНО]** Rustls 0.23.46 TLS stream adapter и тесты TLS handshake/stream exchange/negative trust cases.
- **[РЕАЛИЗОВАНО]** Android system-trust bootstrap и native Rust library build configuration.
- **[РЕАЛИЗОВАНО]** Android app shell, application startup и JNI bootstrap.
- **[РЕАЛИЗОВАНО]** CI для Rust format/lint/tests и сборки Android native libraries для четырёх ABI в базовой конфигурации.
- **[РЕАЛИЗОВАНО]** Документация архитектуры, transport abstraction, VK transport, network state, power efficiency, TLS, packet/MTU и socket contracts.

Ограничения main:
- Android underlay network monitor уже находится в main после merge PR №9; VpnService/TUN lifecycle находится в PR №10, а TUN пока не обрабатывает пакеты;
- нет end-to-end VPN data path;
- нет VK credential provider и live VK Calls TURN adapter;
- нет DTLS-SRTP/SRTP production implementation;
- нет выбранного и интегрированного WireGuard engine;
- нет Gateway и серверного deploy;
- нет device-level подтверждения реальной сети.

### 14.2. PR №4 — Android protected UDP foundation, слит в main

PR: https://github.com/Ghalgha/Ghoncha/pull/4  
Merge commit: `202af0e618c1da676add6912c99afd7a61f1bb30`  
Состояние: **[РЕАЛИЗОВАНО В MAIN]**.

- **[РЕАЛИЗОВАНО]** Testable Kotlin boundary для подготовки unconnected UDP socket.
- **[РЕАЛИЗОВАНО]** Порядок `VpnService.protect()` до `Network.bindSocket()`; fail-closed с закрытием сокета при ошибке.
- **[РЕАЛИЗОВАНО]** Underlay UDP socket factory: host/port validation, network-scoped DNS, IPv4/IPv6 family selection, ephemeral local bind, nonblocking mode и network-generation checks.
- **[РЕАЛИЗОВАНО]** Android wrapper для реальных Network/VpnService callbacks.
- **[РЕАЛИЗОВАНО]** JVM regression tests для socket preparation/factory.
- **[РЕАЛИЗОВАНО]** JNI UDP FD duplication/adoption, native socket registries и close paths.
- **[РЕАЛИЗОВАНО]** Android UDP socket adapter для TURN datagram contract.
- **[РЕАЛИЗОВАНО]** Fixed-capacity `poll(2)` readiness poller и TURN UDP deadline/wait-duration primitives.
- **[НЕ РЕАЛИЗОВАНО]** Persistent multi-allocation TURN runtime, packet routing и единый TUN/TURN/TLS reactor.

CI PR №4 прошёл: Rust format/Clippy/workspace tests и Android debug build. Физическое устройство, живой TURN relay и end-to-end forwarding не проверены.

### 14.3. PR №8 — heap-backed TURN queues

Ветка: `work/heap-backed-turn-queues-main`  
HEAD: `0f0d2c9972eb97d1e4391f36bea1de99c69e7d86`  
PR: https://github.com/Ghalgha/Ghoncha/pull/8  
Основан непосредственно на `main`. Состояние: **слит в main через squash**; CI PASS. Merge commit: `db03aa084f544c1f2f58237fee85500a6402b977`.

- **[РЕАЛИЗОВАНО]** Heap-backed bounded TURN send queues с сохранением compile-time record/byte limits.
- **[РЕАЛИЗОВАНО]** Fallible queue allocation и `TurnError::AllocationFailed` в `TurnUdpDriver::new`.
- **[CI PASS]** Rust format, Clippy, workspace tests и Android debug build.
- PR №5 и PR №6 закрыты без слияния; PR №8 — чистая main-based замена PR №6.

### 14.4. PR №9 — Android underlay network monitor

Ветка: `work/android-underlay-network-monitor-main`  
HEAD: `62e7a65a5c7df79f4a96a7c5fb422b6921ab661d`  
PR: https://github.com/Ghalgha/Ghoncha/pull/9  
Основан непосредственно на `main`. Состояние: **слит в main через merge commit**; все CI задачи прошли. Merge commit: `53ce92bc33d1bde7dc227d412918d5018cda5483`.

- **[РЕАЛИЗОВАНО]** Монитор кандидатов с `NET_CAPABILITY_INTERNET` и `NET_CAPABILITY_NOT_VPN`; автоматический выбор preferred network намеренно не выполняется.
- **[РЕАЛИЗОВАНО]** Snapshot capabilities, validation, metering и transport flags.
- **[РЕАЛИЗОВАНО]** Monotonic per-network generation invalidation при изменении capabilities/link properties и потере сети.
- **[РЕАЛИЗОВАНО]** Unit tests для generation registry.
- В PR №9 добавлен CI trigger для следующей stacked ветки PR №10.
- PR содержит 5 файлов, включая workflow trigger.
- Device-level handover не проверен.
- PR №7 закрыт без слияния; PR №9 — чистая main-based замена.

### 14.7. PR №11 — heap-owned multi-allocation TURN runtime core

Ветка: `work/native-turn-runtime-core`  
PR: https://github.com/Ghalgha/Ghoncha/pull/11  
HEAD: `d518e0205db9c3fc36463adc1032f68fc98467b0`  
Основан на `main`; открыт draft. Последний CI run `42394255925` на HEAD `d518e0205db9c3fc36463adc1032f68fc98467b0`: Rust format/Clippy/workspace tests PASS; Android debug job выполняется, JVM tests, APK builds и ABI packaging ещё не завершены.

- **[РЕАЛИЗОВАНО В PR №11]** Bounded slot owner с одним `Box<TurnUdpDriver<S>>` на allocation и fallible box allocation.
- **[РЕАЛИЗОВАНО В PR №11]** Opaque registration tokens, earliest protocol deadline, bounded timer scanning с persistent cursor, readiness dispatch и pending-output query.
- **[РЕАЛИЗОВАНО В PR №11]** Тесты ownership, identity, timer scheduling, readiness flush, removal и work budget.
- **Не реализовано:** Android poller wiring, worker thread, TUN polling, packet router integration, real network/device verification.

### 14.5. PR №10 — Android VpnService и TUN descriptor lifecycle

Ветка: `work/android-vpnservice-tun-lifecycle-v2`  
HEAD: `fd8b39bf2484478a4381e6c9c86cda906d84df6e`  
PR: https://github.com/Ghalgha/Ghoncha/pull/10  
После merge PR №9 перенаправлен на `main`. Состояние: открыт, **Ready for review**, не слит. CI run `42393331923` полностью PASS: Rust format/Clippy/workspace tests, Android JVM tests, debug/release APK и native packaging для четырёх ABI. Review threads отсутствуют.

- **[РЕАЛИЗОВАНО В PR №10]** Android `VpnService` declaration, VPN consent flow и foreground notification lifecycle.
- **[РЕАЛИЗОВАНО В PR №10]** Локальный TUN с IPv4 host address, без IP routes и без перехвата пользовательского трафика.
- **[РЕАЛИЗОВАНО В PR №10]** `ParcelFileDescriptor.detachFd()` ownership transfer в Rust `OwnedFd` registry.
- **[РЕАЛИЗОВАНО В PR №10]** Native `FD_CLOEXEC`/`O_NONBLOCK`, close handle и native take API для будущего packet runtime.
- **[РЕАЛИЗОВАНО В PR №10]** Kotlin closeable handle и JVM tests для close/transfer semantics.
- **[ВАЖНО]** Это только lifecycle test. Нет TUN packet worker, чтения/записи IP packets, маршрутов, TURN allocation или end-to-end VPN. Always-on VPN выключен.
- Device verification, включая Android 14+ system-exempted foreground-service eligibility, ещё не выполнена.

### 14.6. Другие открытые изменения

- PR №2 — TURN graceful drain и flow-affinity lookup. Открыт, не слит. Не считать частью `main` или ветки PR №4, пока это отдельно не подтверждено merge/commit history.
- PR №3 — дополнительная валидация IPv6 extension chains. Открыт, не слит. Не считать частью `main` или ветки PR №4, пока это отдельно не подтверждено merge/commit history.

Создавать отдельный PR, когда граница изменения и зависимость от предыдущего этапа делают review/merge логичнее; допускаются stacked PR с явным base. Не создавать PR только ради формальности. Не сливать PR без явного разрешения пользователя.

## 15. Критические отсутствующие части

Следующие компоненты являются блокирующими для полноценного VPN:

1. Android `VpnService`, TUN create/close, foreground lifecycle и permission handling.
2. Android network callback/state snapshot/generation integration.
3. Persistent native runtime, который владеет несколькими `TurnUdpDriver`, сокетами, очередями и таймерами.
4. Unified reactor для TUN, TURN UDP/TCP/TLS и timers.
5. Интеграция packet engine ↔ tunnel engine ↔ transport adapter.
6. VK Calls manual credential workflow.
7. VK Calls authorized automatic credential workflow.
8. Реальный VK TURN interoperability и корректная обработка credential refresh/expiry.
9. DTLS-SRTP handshake, gateway identity verification, RTP/SRTP protect/unprotect и replay handling.
10. Выбор и интеграция VPN tunnel engine.
11. Ghoncha Gateway, peer provisioning, forwarding/NAT/firewall и server control plane.
12. SSH deployment/upgrade/rollback и server lifecycle management в приложении.
13. UI, live profile switching и end-to-end diagnostics.
14. Дополнительные transport adapters.
15. iOS, Windows, Linux и OpenWrt platform adapters.
16. Тесты на физических устройствах и реальных ограниченных сетях.
17. Измерения battery drain, thermal, CPU, memory, latency, jitter, loss и goodput.

## 16. Обязательная последовательность разработки

Не перескакивать между независимыми подсистемами. Следующий этап начинается после завершения текущего этапа, прохождения его тестов и обновления документации. Если обнаружен блокер, сначала устранить его или оформить ADR/изменение плана; не начинать параллельную несвязанную функцию.

Рекомендуемый порядок:

### Этап A — завершение Android socket foundation
- проверить текущий PR diff и ownership semantics;
- закрыть все ошибки FD ownership, stale generation и close ordering;
- подтвердить Android NDK build и JVM tests;
- добавить device/instrumentation tests для protect/bind/route;
- не объявлять transport runtime готовым до реальной проверки.

### Этап B — Android VPN lifecycle
- реализовать VpnService и user consent;
- создать TUN и формализовать FD ownership;
- подключить NetworkCallback и network snapshots;
- протестировать reconnect, permission revoke, stop/start и handover.

### Этап C — единый Rust runtime
- спроектировать heap-owned multi-allocation runtime;
- интегрировать AndroidUdpPoller и TURN UDP drivers;
- обрабатывать readiness, timers, bounded batches, WouldBlock и fatal errors;
- unregister poller до закрытия socket;
- избегать больших stack allocations и unbounded queues;
- интегрировать TUN readiness в общий event loop.

### Этап D — проверенный VPN tunnel engine
- принять отдельное решение по WireGuard implementation;
- проверить лицензии, криптографию, API, target builds и interoperability;
- интегрировать один узкий vertical slice с loopback/integration tests;
- не добавлять следующий transport, пока этот путь не стабилен.

### Этап E — VK Calls credentials и carrier
- сначала ручной link/hash сценарий;
- затем TURN credential parsing/validation и lifecycle;
- затем автоматизированный authorized VK session provider;
- затем DTLS-SRTP/SRTP и gateway identity;
- после этого live TURN interoperability и end-to-end packet flow.

### Этап F — Ghoncha Gateway
- определить peer provisioning и config format;
- реализовать Gateway data plane;
- добавить forwarding/NAT/firewall policy;
- провести interoperability и load/security tests.

### Этап G — SSH deployment и управление
- host key verification и credential handling;
- install/upgrade/rollback;
- server lifecycle, health checks, logs/metrics;
- end-to-end deploy-and-connect tests.

### Этап H — профили, UX и performance
- связать уже существующую profile policy с runtime;
- реализовать live resize/drain;
- добавить UI, диагностику и пользовательский speed test;
- провести device-side battery/performance measurement.

### Этап I — дополнительные платформы и транспорты
- стабилизировать общие Rust contracts;
- переносить на платформы по одной;
- добавлять транспорты по одному с interoperability и security tests.

Порядок может меняться только при наличии конкретной технической зависимости или доказанного блокера. Причина изменения должна быть записана в этом файле.

## 17. Правила работы разработчика и AI-агента

### 17.1. Перед изменением кода
1. Прочитать этот файл и относящиеся к текущей задаче документы.
2. Проверить текущую ветку, HEAD, незакоммиченные изменения и состояние PR.
3. Просмотреть реальные исходники и тесты затрагиваемого компонента.
4. Сформулировать одну ограниченную цель текущего шага.
5. Проверить зависимости, API, платформенные ограничения, лицензии и security implications.
6. Составить критерии завершения до написания кода.

### 17.2. Во время реализации
- Работать последовательно, небольшими логически завершёнными изменениями.
- Не менять несколько независимых подсистем в одном шаге.
- Не добавлять абстракции «на будущее» без текущего доказуемого использования.
- Не оставлять заглушки, которые выглядят как рабочая функциональность.
- Не скрывать ошибки через permissive fallback.
- Не менять публичные contracts без проверки всех call sites и тестов.
- При изменении протокольного поведения сверять реализацию с RFC и проверяемыми interoperability vectors.
- Для безопасности предпочитать fail-closed поведение.
- Сохранять bounded memory/CPU/time/resource behavior.
- Создавать PR, когда это необходимо для логичного разделения изменений, независимого review, управления зависимостями или безопасного продолжения работы; не создавать PR ради формальности.
- Не откладывать слияние готового PR без конкретной технической, качественной или организационной причины.
- Готовый PR следует сливать в ближайшем рабочем цикле после прохождения обязательных CI-проверок, разрешения замечаний review и выполнения зависимостей. Для stacked PR соблюдать порядок зависимостей.
- Сливать PR только после прямого разрешения пользователя. Запросить его сразу, когда PR готов к слиянию; после получения разрешения не задерживать merge без конкретного блокера.

### 17.3. После каждого логического шага
1. Запустить узкие тесты изменённого компонента.
2. Запустить форматирование и lint.
3. Запустить связанные crate/workspace tests.
4. Проверить Android build, если затронуты Android/JNI/NDK.
5. Проверить регрессии и ownership/error paths.
6. Обновить соответствующую документацию.
7. Обновить этот файл, если изменились статус, архитектура, решение, блокер, порядок этапов или критерии готовности.

Не заявлять тест успешным, если он не запускался или его результат неизвестен. Разделять CI, локальные тесты, integration tests и device tests.

### 17.4. Полный аудит каждые 50 шагов
После каждых **50 завершённых существенных шагов разработки** выполнить полный внутренний аудит проекта. Аудит не является отдельным пользовательским уведомлением и не требует прерывать обычный ход работы ради отчёта.

Полный аудит включает:
- сверку фактического кода с архитектурой и этим контекстом;
- поиск расхождений между документацией, кодом и тестами;
- review ownership/lifetime, concurrency, cancellation и stale event handling;
- security review credentials, key material, TLS identity, replay protection и logging;
- проверку bounded buffers/queues, таймеров, retries, memory/CPU и battery impact;
- проверку platform-specific assumptions и portability;
- анализ тестового покрытия, отрицательных сценариев и пропущенных interoperability tests;
- анализ зависимостей, лицензий, обновлений и известных уязвимостей;
- проверку CI, веток, PR и того, что считается merged/unmerged;
- корректировку roadmap и PROJECT_CONTEXT.md.

Счётчик увеличивается только после завершённого логического шага с проверками. Исправление документа без изменения реализации само по себе не считается шагом разработки. После аудита продолжать последовательную работу; сообщать пользователю только обычный запрошенный результат, если он отдельно не попросил аудит.

### 17.5. Периодическая проверка PROJECT_CONTEXT.md
Проверять актуальность, согласованность статусов, архитектуры, roadmap и фактического состояния `main`/PR каждые **20 завершённых существенных шагов разработки**. Проверка не заменяет немедленное исправление документа при подтверждённом изменении фактов.

### 17.6. Обновление PROJECT_CONTEXT.md
Этот файл — живой источник истины, а не документ, который обновляется только в конце проекта.

Обновлять его обязательно:
- при получении новой подтверждённой технической информации;
- если новая информация опровергает или уточняет существующее утверждение;
- при изменении архитектуры или принятии/отмене решения;
- при начале, завершении или блокировке этапа;
- при изменении состава реализованных функций;
- при добавлении/удалении зависимостей, платформ или транспортов;
- при изменении статуса PR/branch/commit, если это влияет на статус реализации;
- после каждого этапа реализации и его проверок.

Если утверждение опровергнуто, исправить его в том же рабочем цикле. Не оставлять известную ошибку с пометкой «потом обновить». Для важных решений указывать дату, основание и затронутые компоненты. Не записывать предположение как факт: помечать его как гипотезу или требование проверки.

## 18. Definition of Done

Компонент считается завершённым только когда:
- реализован требуемый функционал, а не только интерфейс или типы;
- определены ownership, lifecycle, concurrency и error semantics;
- обработаны timeout, cancellation, stale generation и resource exhaustion;
- есть позитивные, негативные и regression tests;
- пройдены форматирование, lint и соответствующие сборки;
- для сетевого протокола есть interoperability tests;
- для Android есть необходимые device/instrumentation tests;
- документация отражает фактическое поведение;
- PROJECT_CONTEXT.md обновлён;
- нет ложного заявления о production readiness.

Ghoncha в целом не считается полноценным VPN до прохождения end-to-end сценария: установка/запуск клиента → разрешение VPN → TUN → защищённый tunnel engine → VK Calls TURN transport → аутентифицированный Ghoncha Gateway → маршрутизация IPv4/IPv6 → обратный трафик → корректное восстановление после network handover.

## 19. Источники технических требований

При реализации использовать первичные спецификации и официальную платформенную документацию:
- TURN — RFC 8656: https://www.rfc-editor.org/rfc/rfc8656
- DTLS-SRTP — RFC 5764: https://www.rfc-editor.org/rfc/rfc5764
- SRTP AES-GCM — RFC 7714: https://www.rfc-editor.org/rfc/rfc7714
- WireGuard protocol — https://www.wireguard.com/
- Android VpnService — https://developer.android.com/reference/android/net/VpnService
- Android VPN guide — https://developer.android.com/develop/connectivity/vpn
- Android Network — https://developer.android.com/reference/android/net/Network
- Rust documentation — https://doc.rust-lang.org/

Ссылки не заменяют проверку конкретной версии API, исходного кода зависимости, лицензии, платформенной сборки и реального поведения.

---

## 19.1. Полевые наблюдения по ограниченным сетям (2026-11-07)

Внешний источник для анализа: тема 4PDA «Суверенный Интернет» (https://4pda.to/forum/index.php?showtopic=1110469), включая сообщение пользователя https://4pda.to/forum/index.php?showtopic=1110469&view=findpost&p=145214858. Прямое открытие указанного сообщения в момент проверки было недоступно (HTTP 403/ошибка источника); поэтому ниже зафиксированы только независимо доступные индексированные фрагменты темы и наблюдения, которые нельзя считать лабораторно подтверждёнными.

Практические выводы для дальнейшей проверки Ghoncha:

1. **Разделять DPI-блокировку и режим белого списка.** В теме прямо отмечается, что изменение DNS/SNI, TLS fingerprint или фрагментация ClientHello не восстанавливают путь, если сеть вообще не разрешает соединение с адресом/портом сервера. Диагностика должна сначала классифицировать отказ: DNS, IP reachability, TCP/UDP handshake, TURN allocation, DTLS/SRTP handshake или внутренний VPN.
2. **Не считать доступность глобальной.** Пользователи сообщают о различиях между регионами, операторами, сетевыми режимами и даже отдельными периодами работы сети. Сервер/relay, доступный в одной точке, не подтверждает доступность в другой. Нужны измерения по матрице оператор × регион × тип доступа × время и безопасная адаптация транспортных параметров без жёстко зашитых «универсальных» адресов.
3. **Проверять VK Calls TURN в реальной сети, а не по списку разрешённых доменов.** Тема упоминает перенос WireGuard/Hysteria через VK Calls TURN с DTLS 1.2. Это подтверждает релевантность выбранного транспортного направления, но не доказывает совместимость конкретного протокольного стека Ghoncha. Требуются отдельные interoperability tests для TURN, DTLS-SRTP, SRTP, Gateway identity и полного двустороннего VPN-пути.
4. **Не переносить настройки TLS-маскировки на другой протокол автоматически.** Сообщения о смене uTLS fingerprint и фрагментации TLS ClientHello относятся к TLS/VLESS-сценариям. Они не являются готовым решением для DTLS-SRTP или TURN и могут нарушить совместимость либо ухудшить безопасность. Любой подобный эксперимент — только в соответствующем transport adapter, с протокольной проверкой и без отключения аутентификации/проверки сертификатов.
5. **Измерять деградацию и ограничивать параллелизм.** В теме встречаются сообщения о таймаутах при увеличении числа потоков и о временных/периодических отказах. Профили Unlimited/Standard/EnergySaving должны опираться на измерения потерь, RTT, jitter, goodput, CPU и батареи; увеличение потоков не должно быть безусловной реакцией на низкую скорость.
6. **Учитывать поверхность атаки управляющей инфраструктуры.** Обсуждение отдельно обращает внимание на риск дополнительных публичных панелей управления VPS. Для Ghoncha сохранять минимальный control plane, SSH host-key verification, минимальные привилегии, отсутствие публичной административной панели по умолчанию и аудит действий deployment.
7. **Считать сторонние подписки и конфигурации недоверенным вводом.** Не импортировать конфигурации автоматически без проверки схемы, размеров, адресов, разрешённых транспортов и параметров криптографии. В перспективе — подпись/проверка происхождения собственных конфигураций, защита секретов и исключение credentials из логов.
8. **Не принимать слабые экспериментальные каналы за основной транспорт.** Упоминания DNS-туннелей сопровождаются крайне низкой пропускной способностью и неполной проверкой утечек. Это не основание менять основной дизайн Ghoncha; альтернативный транспорт допустим только после threat model, оценки утечек и измерений.

Эти наблюдения превращены в проверочные требования, а не в утверждения о гарантированном обходе. Не использовать опубликованные в теме списки SNI, IP, бесплатные подписки или чужие credentials как production-конфигурацию Ghoncha.

---

## 20. Последняя проверка и открытые ограничения

Состояние проверено после merge PR №8 (`db03aa084f544c1f2f58237fee85500a6402b977`) и PR №9 (`53ce92bc33d1bde7dc227d412918d5018cda5483`). `PROJECT_CONTEXT.md` является каноническим документом и редактируется только в корне ветки `main`; не добавлять его в PR diff и не вносить в него изменения из рабочих веток. Изменения контекста вносить непосредственно в `main`.

- PR №4, PR №8 и PR №9 слиты в main; CI для PR №8/9 прошёл полностью.
- Отображаемое имя Android-приложения установлено как `Ghoncha`; manifest использует `@string/app_name`. Эти изменения находятся в main на HEAD `75875988a2888d33932279429c7dbb6fb6e35c68`. CI для исправления имени приложения прошёл полностью в run `42394570576`.
- PR №10 Ready for review, не слит. Его исходный CI run `42393331923` прошёл полностью до изменения app label; label correction добавлен в ветку PR10 на HEAD `83e7062658f7964891ea8b2956f44556d7c45362`, но для этого HEAD пока нет подтверждённого CI run.
- PR №11 был Ready for review и добавлял платформенно-независимый multi-allocation TURN runtime core. Полный CI run `42395344907` прошёл на HEAD `93a2ba15188631a2f16f8f6b550eb592ceb0b56b` (Rust format, Clippy, workspace tests, Android JVM tests, debug/release APK и native packaging четырёх ABI). 2026-11-07 PR №11 слит squash по прямому разрешению пользователя; merge commit `53cdf81adea6e04e26f0af6dfa17bc5701c6f713`.
- В PR №11 исправлено обновление protocol deadline после socket readiness: после обработки входных TURN-событий runtime повторно опрашивает driver и сохраняет актуальный deadline.
- PR №12 draft, stacked на PR №11: `AndroidTurnUdpRuntime` соединяет adopted UDP socket handles, `AndroidUdpPoller` и `TurnUdpRuntime`; обрабатывает readiness, TURN timers, writable interest, очередь peer payload и unregister-before-close. Поток намеренно не создаётся: lifecycle owner должен сериализовать вызовы и остановиться до drop runtime. На HEAD `7535300503c58dbd8cc761ecc5b9a4e6b8e69ad7` полный CI run `42395654747` завершился PASS: Rust format, Clippy, workspace tests, Android JVM tests, debug/release APK и native packaging четырёх ABI. PR остаётся draft и не слит.
- Успешный CI не доказывает работу на физическом устройстве, совместимость с живым VK TURN relay, корректность маршрута в ограниченной сети или наличие end-to-end VPN.
- PR №2 и PR №3 остаются отдельными открытыми изменениями и не включены в статус `main`.
- `PROJECT_CONTEXT.md` — единственная каноническая копия в `main`; отсутствие этого файла в остальных ветках является намеренным.


- Повторная проверка 2026-11-07: PR №11 HEAD `93a2ba15188631a2f16f8f6b550eb592ceb0b56b`, CI run `42395344907` PASS, review threads/reviews отсутствуют; GitHub PR API сообщает `mergeable=true`, `mergeable_state=clean`. Compare `main...work/native-turn-runtime-core` показывает `diverged` (12 commits ahead / 12 behind), но GitHub считает PR технически mergeable. PR №11 готов к слиянию; требуется отдельное прямое разрешение пользователя, до него не сливать. PR №10 остаётся open; его HEAD `83e7062658f7964891ea8b2956f44556d7c45362` не имеет подтверждённого CI run, `mergeable=false`/`dirty`. PR №12 остаётся draft, CI PASS, зависит от PR №11.

**Текущая последовательность:** PR №11 технически готов к merge, ожидает прямого разрешения пользователя. PR №12 draft и зависит от PR №11. PR №10 требует CI на актуальном HEAD и устранения mergeability blocker. PR №10, PR №11 и PR №12 не сливать без прямого разрешения. После стабилизации PR №11/12 и PR №10 следующий этап — service-owned worker с явной cancellation/join семантикой, затем TUN readiness и packet router. После этого выполнить device-level проверки; не объявлять VPN рабочим до end-to-end теста.


---

## 21. Проверка гипотез о сигнатурной блокировке CSQTT/WDTT (2026-11-07)

Пользователь предоставил четыре фрагмента предполагаемых правил EcoDPI/RDP.ru, Suricata/Snort, XDP/eBPF и iptables/nftables. Их происхождение и соответствие реальному формату ТСПУ не подтверждены. Не считать их опубликованной конфигурацией РКН, фактическим правилом оператора или доказательством возможности массовой селективной блокировки за 15 минут.

### 21.1. Протокольные утверждения

- RFC 5764 описывает DTLS-SRTP: SRTP-пакеты не должны обрабатываться до завершения DTLS handshake. Это требование относится к корректной ассоциации DTLS-SRTP, но само по себе не позволяет DPI надёжно заключить, что любой первый наблюдаемый RTP-пакет был отправлен без handshake.
- Первый байт в диапазоне 0x80–0xBF используется демультиплексированием DTLS-SRTP для классификации RTP/RTCP. Это классификационный диапазон, а не уникальная сигнатура CSQTT или доказательство нарушения протокола.
- RFC 7675 определяет ICE consent freshness через аутентифицированный STUN Binding Request/Response. Это не универсальное требование отправлять такой запрос в каждом произвольном UDP/TURN потоке и не тождественно любому механизму поддержания NAT mapping.
- Однобайтовый UDP payload 0xFF сам по себе не доказывает нарушение WebRTC или использование конкретного туннеля. Для вывода о его значении нужна спецификация исследуемого клиента/транспорта или захват трафика с подтверждённым контекстом.
- Строки CQF1, READY_OK, GETCONF: в примерах являются гипотетическими маркерами. Без исходного кода/протокольной спецификации и реального packet capture нельзя утверждать, что они действительно передаются в открытом виде или уникальны для конкретного проекта.

### 21.2. Ошибки и ограничения приведённых фильтров

- JSON-профиль содержит HTML-escaped символы и экранированные имена полей в опубликованном виде; это невалидный JSON без предварительного декодирования. Схема EcoDPI / RDP.ru не подтверждена и не должна восприниматься как реальный формат конфигурации ТСПУ.
- Suricata/Snort: тест byte_test:1,=,0x80,0 проверяет ровно 0x80, а не весь заявленный диапазон 0x80..0xBF; flow:established для UDP не доказывает, что сенсор видел DTLS handshake или начало сессии. dsize:>40 — эвристический порог, не доказательство SRTP. Строковые совпадения могут давать ложные срабатывания, если маркеры не уникальны и не привязаны к проверенному формату.
- XDP: код проверяет только Ethernet IPv4 UDP и не покрывает IPv6/VLAN. Не проверяет допустимость ihl и полную длину IPv4 header до вычисления UDP pointer, IP total length, UDP length и корректную обработку фрагментов. Использование __constant_ntohs для runtime-поля UDP length некорректно; требуется runtime byte-order conversion после валидации. Поэтому пример не является безопасным готовым XDP-фильтром.
- iptables: поиск строк через -m string — поиск байтов в пакете, а не распознавание состояния протокола. Пример u32 с @0 не выражает надёжную проверку первого байта UDP payload: вычисляемый offset не включает UDP header. Условие общей длины 29 байт предполагает IPv4 без options и фиксированный заголовок.
- nftables: приведённые выражения зависят от контекста семейства/цепочки и offset относительно транспортного заголовка; фиксированная длина IPv4 и фиксированные порты не являются универсальным детектором. Синтаксическую валидность и семантику нужно проверять отдельно на целевой версии nftables.

### 21.3. Инженерные решения для Ghoncha

1. Не добавлять в Ghoncha намеренно фиктивные keepalive, повреждённые DTLS/SRTP последовательности или обходные модификации ради подгонки под гипотетические сигнатуры.
2. Реализовать только те протокольные слои, которые фактически используются выбранным VK Calls TURN режимом. TURN allocation/Refresh, permissions и ChannelBind проверять по RFC 8656; ICE connectivity/consent freshness применять только если конкретная интеграция действительно использует ICE; DTLS-SRTP реализовывать только если подтверждено, что он является частью фактического media/data path. Не переносить требования WebRTC на произвольный TURN payload.
3. Не использовать отсутствие наблюдаемого handshake как основание менять криптографию, отключать проверки или подделывать протокольное состояние.
4. В диагностике разделять отказ DNS/IP reachability, TURN allocation, ICE/consent, DTLS handshake, SRTP authentication и внутреннего VPN-туннеля.
5. Проверять false-positive/false-negative только на собственных контролируемых packet captures и тестовых сетях. Не заявлять гарантированную устойчивость к DPI или работу в сетях белых списков.
6. Не переносить синтаксис этих примеров в production, не строить на нём архитектурные решения и не использовать как основание для заявления о том, что конкретный внешний проект блокируется указанным способом.


## 22. Уточнение состояния после слияния PR №11 (2026-11-07)

- PR №11 слит squash по прямому разрешению пользователя: merge commit `53cdf81adea6e04e26f0af6dfa17bc5701c6f713`; CI PASS run `42395344907` на PR HEAD `93a2ba15188631a2f16f8f6b550eb592ceb0b56b`.
- Main HEAD после слияния: `53cdf81adea6e04e26f0af6dfa17bc5701c6f713`.
- PR №12 остаётся draft, HEAD `7535300503c58dbd8cc761ecc5b9a4e6b8e69ad7`, CI PASS run `42395654747`, base всё ещё `work/native-turn-runtime-core`. Эта base branch уже слита squash, поэтому PR12 нельзя просто ретаргетить на main без проверки: squash merge не сохраняет исходную ancestry PR11, и это может продублировать PR11 изменения в diff. Следующая задача — безопасно перебазировать/пересобрать только изменения PR12 поверх актуального main, проверить diff, оставить PR12 draft до полного CI и ревью.
- PR №10 остаётся open, HEAD `83e7062658f7964891ea8b2956f44556d7c45362`; CI run на актуальном HEAD отсутствует. Mergeability требует повторной проверки после обновления ветки.


## 23. Политика устойчивости к сетевым ограничениям и энергоэффективности (2026-11-07)

Требование пользователя: максимально высокий практический уровень устойчивости к блокировкам и сетевым ограничениям в рамках архитектуры Ghoncha, без необоснованного ухудшения скорости, задержки, стабильности или автономности. Не обещать гарантированный обход DPI, ТСПУ, белых списков или региональных ограничений.

### 23.1. Приоритеты проектирования

1. Сначала корректная криптография, аутентификация, проверка целостности и протокольное состояние. Никакие эвристики DPI не оправдывают ослабление криптографии, повторное использование ключей/nonce или игнорирование ошибок аутентификации.
2. Основной транспорт остаётся VK Calls TURN. Устойчивость строится на корректной реализации и проверке нескольких реально доступных вариантов транспорта/маршрута, а не на фиктивном трафике или недоказанных сигнатурных обходах.
3. Разделять control plane, transport plane и IP data plane. Сбой DNS, сигнализации/credential refresh, TURN allocation, UDP reachability, consent, DTLS, SRTP и внутреннего forwarding должен иметь отдельный диагностический код и отдельную стратегию восстановления.
4. Поддерживать безопасную деградацию и переключение только между проверенными вариантами: например, доступный TURN transport/path, повторная allocation, обновление credentials, смена underlay network. Не объявлять fallback доступным, пока не подтверждена его реальная совместимость с VK Calls и Gateway.
5. Учитывать allowlist-сети как отдельный сценарий угроз: тестировать доступность bootstrap, DNS, адресов/портов и выбранного transport на реальных тестовых сетях. Нельзя делать вывод о проходимости по одной сигнатуре или по одному оператору/региону.

### 23.2. DPI и протокольная устойчивость

- Не отправлять открытые внутренние команды, статические magic values или диагностические маркеры в пользовательском transport payload без необходимости и документированной причины. Протокольные поля должны быть аутентифицированы и защищены в пределах выбранного протокола.
- Не добавлять random padding, dummy packets, фальшивые keepalive, искусственные DTLS/SRTP последовательности или packet mutation как глобальные настройки по умолчанию. Такие меры могут увеличить трафик, задержку, расход CPU/радио и ухудшить interoperability, не гарантируя обход.
- Не полагаться на маскировку по первому байту, фиксированным размерам пакета, одному ClientHello fingerprint или одному UDP payload. Детекторы и фильтры могут меняться; сигнатуры — лишь один слой риска.
- Не отключать certificate/peer authentication, DTLS/SRTP authentication, ICE consent или replay protection ради совместимости с фильтром.
- Поддерживать обновляемую матрицу interoperability и сетевой доступности по транспорту, Android API, оператору/типу сети и региону. Собирать только минимальные обезличенные метрики и не сохранять пользовательские payloads.
- Вся логика адаптации должна опираться на измеренные результаты и ограниченные таймауты/backoff, а не на бесконечные повторы.

### 23.3. Энергоэффективность и производительность

- Event-driven I/O; никаких busy loops и постоянного polling без ожидающих событий.
- Один управляемый runtime/worker на активную VPN-сессию, если измерения не докажут необходимость другого дизайна. Не плодить конкурирующие потоки на каждый allocation.
- Использовать существующие TURN deadlines и poller readiness; объединять таймеры и события, ограничивать работу за один tick и применять backoff при сетевых отказах.
- Не держать параллельные fallback-сессии постоянно активными без доказанной необходимости. По умолчанию — последовательная проверка/переключение; короткий overlap допускается только при измеренной пользе и ограниченном бюджете.
- Не отправлять лишние keepalive: использовать требования конкретного протокола, наблюдаемое поведение NAT/сети и корректные интервалы. Для ICE consent freshness соблюдать RFC 7675, не подменяя его произвольным однобайтовым UDP ping.
- Сокеты, DNS результаты и allocation переиспользовать в пределах их корректного жизненного цикла; закрывать неиспользуемые ресурсы. Не запускать активное сканирование сети в фоне.
- Любое усложнение транспорта должно сопровождаться измерением latency, jitter, loss, goodput, CPU wakeups, CPU time, bytes sent/received и battery drain на одинаковых сценариях.
- Профили Unlimited, Standard и EnergySaving должны управлять частотой фоновых операций, параллелизмом и допустимой скоростью восстановления, но не снижать уровень криптографической защиты.

### 23.4. Проверяемая нормативная база

На дату этого обновления базовые ориентиры включают RFC 8656 (TURN), RFC 8827 (WebRTC Security Architecture), RFC 8835 (Transports for WebRTC), RFC 5764 (DTLS Extension to Establish Keys for SRTP) и RFC 7675 (STUN Usage for Consent Freshness). RFC 8656 задаёт независимые жизненные циклы: TURN allocation по умолчанию 600 секунд с Refresh примерно за минуту до истечения, permissions — 300 секунд, ChannelBind — 600 секунд; ChannelBind одновременно обновляет permission. RFC 7675 задаёт ICE consent freshness с аутентифицированным STUN Binding Request/Response и 30-секундным сроком consent; это не заменяет TURN Refresh/permission/ChannelBind и не должно добавляться к не-ICE транспортам автоматически. RFC 8827/8835/5764 относятся к WebRTC security/media transport; применять их только к подтверждённым WebRTC слоям. Реализацию сверять с актуальными редакциями RFC и опубликованными errata перед каждой соответствующей подсистемой.

## 24. Состояние интеграции после переноса PR №12 на main (2026-11-07)

- PR №11 уже слит; main содержит TURN runtime core.
- PR №12 (ветка work/android-turn-udp-runtime-owner) перенесён на актуальную main ancestry после squash merge PR №11. Base PR — main; HEAD на момент записи: 330f3deb04d35b7c4582fe17ca216df226245ef7. Diff: шесть целевых файлов (workflow trigger, Cargo.lock, platform-android Cargo.toml/lib.rs, transport-turn runtime.rs, Android UDP contract docs); PROJECT_CONTEXT.md в diff отсутствует.
- PR №12 остаётся draft. Полный CI run 42399407436 на текущем HEAD: Rust format PASS, Clippy PASS, workspace tests PASS; Android job ещё выполняется (JVM tests, APK builds и native packaging ожидают завершения). Review threads/reviews отсутствуют. Не объявлять готовым к merge до полного Android CI и выхода из draft; прямого разрешения на merge PR12 нет.
- В workflow pull_request branch filter добавлена ветка PR12, чтобы дальнейшие изменения PR, нацеленного на main, получали CI.
- PR №10 остаётся open, HEAD 83e7062658f7964891ea8b2956f44556d7c45362; CI на этом HEAD не обнаружен. Не объявлять готовым к merge. Его Android TUN lifecycle и изменения crates/platform-android/src/lib.rs требуют аккуратной интеграции с уже слитым TURN runtime и PR12, без перезаписи изменений соседней ветки.
- Следующая очередность: завершить CI/review PR12 и запросить отдельное разрешение на его merge, затем перенести PR10 на актуальную main с сохранением runtime-кода и выполнить полный CI. После стабилизации этих оснований реализовать service-owned worker с cancellation/join, затем TUN readiness и IP packet router.
