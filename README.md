# «Цифровой город» для группы 2: как запустить

Город состоит из **ядра** (одно на всех, готовое) и **районов** (каждая команда — свой).
Всё работает на вашем компьютере в Docker.

| Часть | Что это | Адрес в браузере |
|---|---|---|
| Шлюз (Caddy) | единственный вход в город, раздаёт запросы районам | http://city.localhost:8080 |
| Паспортный стол (Keycloak) | единый вход для всех районов, роли | http://auth.city.localhost:8080 |
| Транспорт (NATS) | шина событий и журналов между районами | страницы нет |
| Мэрия | обращения жителей, объявления | http://cityhall.city.localhost:8080 |
| Банк | счета, переводы, касса, контроль | http://bank.city.localhost:8080 |
| Больница | медкарты, роли врач / пациент / регистратура | http://hospital.city.localhost:8080 |
| Энергосеть | счётчики, пульт диспетчера | http://grid.city.localhost:8080 |
| Городской SOC | журналы всех районов, тревоги | http://soc.city.localhost:8080 |

> **Честно:** на сервере, где готовились архивы, нет Docker. Код районов проверен тестами (39 проверок),
> шлюз и шина проверены настоящими Caddy и NATS, но **весь город целиком в Docker ещё не запускался**.
> Если что-то не стартует — это ожидаемо для первой версии: пишите ассистенту номер шага и текст ошибки.

## Что нужно

- ЛР0 выполнена: Docker Desktop (Windows / macOS) или Docker (Linux) работает, `docker run hello-world` проходит.
- Память: Docker должен получать **не меньше 4 ГБ**. Ядро занимает около 1,2 ГБ (из них Keycloak — до 1 ГБ),
  каждый район — 60–150 МБ. На компьютере с 8 ГБ закройте лишние вкладки браузера.
- Браузер Chrome, Edge или Firefox: адреса `*.localhost` они открывают сами, настраивать ничего не нужно.

Все команды ниже — **в окне Ubuntu (WSL)** на Windows или в терминале на macOS / Linux.

## Шаг 1. Распаковать архивы

Положите в одну папку `city-core.zip` и архив своего района (`district-bank.zip` и т. п.):

```bash
mkdir -p ~/city && cd ~/city
# скопируйте архивы сюда; из Windows папка «Загрузки» видна как /mnt/c/Users/ВАШЕ_ИМЯ/Downloads
cp /mnt/c/Users/ВАШЕ_ИМЯ/Downloads/city-core.zip /mnt/c/Users/ВАШЕ_ИМЯ/Downloads/district-*.zip .
sudo apt install -y unzip        # если unzip ещё не стоит
unzip city-core.zip
unzip district-bank.zip          # ваш район
ls                               # должны быть папки city-core и district-bank
```

## Шаг 2. Запустить ядро (один раз на компьютер)

```bash
docker network create city       # общая сеть города; ошибка «already exists» — это нормально
cd ~/city/city-core
cp .env.example .env
docker compose up -d
docker compose ps                # gateway, passport, transport — состояние running
```

Паспортный стол (Keycloak) стартует **1–2 минуты**. Проверка — откройте http://city.localhost:8080:
видна страница «Цифровой город». Ссылка «Паспортный стол» должна открыть страницу входа.

## Шаг 3. Запустить свой район

```bash
cd ~/city/district-bank
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"
nano .env                        # вставьте строку вместо «замените-меня» в SECRET_KEY, сохраните: Ctrl+O, Enter, Ctrl+X
docker compose up --build -d
docker compose ps
docker compose logs web          # журнал района: строки в формате JSON
```

Энергосеть: в `.env` замените ещё и `METER_TOKEN` (так же, как SECRET_KEY).

Откройте адрес района (например, http://bank.city.localhost:8080) → «Войти» → вход в Паспортном столе.

## Тестовые жители и сотрудники

Пароль учебных пользователей берётся из `CITY_TEST_PASSWORD` в локальном `city-core/.env`.

| Логин | Роли | Где пригодится |
|---|---|---|
| `ivanov`, `petrova` | житель, пациент | Банк (счета, переводы), Мэрия (обращения), Больница (своя медкарта) |
| `doctor` | врач | Больница: пациенты, записи, статистика |
| `registrar` | регистратура | Больница: завести медкарту (логин жителя, например `ivanov`) |
| `cashier` | кассир | Банк: пополнение счёта |
| `controller` | контролёр_банка | Банк: подтверждение переводов больше 50 000 ₽ |
| `dispatcher` | диспетчер | Энергосеть: отключение и включение кварталов |
| `official` | чиновник | Мэрия: все обращения; Больница: статистика |
| `analyst` | аналитик_soc | SOC: тревоги и журналы |

Чтобы зайти под другим пользователем — нажмите «Выйти» в районе (выход происходит и из Паспортного стола).

## Как устроен район

```
district-bank/
  compose.yaml        как запускается район (без опубликованных портов — только через Шлюз)
  Dockerfile          образ: Python 3.12, пользователь appuser, не root
  .env.example        настройки; ваш .env в Git не попадает
  app/__init__.py     весь код района: страницы и проверки прав (места ИБ помечены «ИБ:»)
  app/templates/      HTML-страницы
  citykit/            общий код города: вход, журнал, события. НЕ меняйте — правки делаются для всех сразу
  tests/              проверки безопасности: pytest
```

Проверки можно запустить без Docker:

```bash
cd ~/city/district-bank
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

## Журналы и события

- Каждый район пишет журнал в формате JSON (соглашение Р4): `docker compose logs web`.
  Копия журнала уходит в Транспорт (тема `city.logs.<район>`), её собирает SOC.
- События между районами (Р5) идут через Транспорт: `city.events.<район>.<объект>.<действие>.v1`.
  Пример: Энергосеть отключила квартал → событие `city.grid.outage.planned.v1` → Мэрия показывает его в «Объявлениях».
- SOC сам забирает из Паспортного стола события входа (удачные и неудачные) и замечает перебор паролей.

## Частые проблемы

| Что видите | Что делать |
|---|---|
| `network city declared as external, but could not be found` | Не выполнен шаг 2: `docker network create city` |
| Страница «Район не запущен» | Район не запущен или ещё стартует: `docker compose ps` и `docker compose logs web` в папке района |
| «Паспортный стол недоступен» при входе | Keycloak ещё стартует (до 2 минут) или упал: `docker compose logs passport` в `city-core` |
| После входа ошибка `invalid_client` или «Вход не удался» | Секрет клиента в `.env` района не совпадает с `CLIENT_SECRET_<РАЙОН>` в `city-core/.env` |
| `Нет SECRET_KEY` в журнале района | Не заменили `замените-меня` в `.env` района (шаг 3) |
| `port is already allocated` для 8080 | Порт занят (часто — контейнер из ЛР0): `docker ps`, остановите лишнее (`docker stop ИМЯ`) |
| Keycloak перезапускается сам (`Exited (137)`) | Не хватает памяти: Docker Desktop → Settings → Resources → Memory не меньше 4 ГБ |
| `*.localhost` не открывается в браузере | Добавьте строки в `C:\Windows\System32\drivers\etc\hosts` (блокнот от имени администратора): `127.0.0.1 city.localhost auth.city.localhost bank.city.localhost cityhall.city.localhost hospital.city.localhost grid.city.localhost soc.city.localhost` |
| Изменили код, а в браузере старое | Пересоберите: `docker compose up --build -d` |

## Остановить и начать заново

```bash
docker compose down              # в папке района или ядра: остановить (данные сохраняются)
docker compose down -v           # остановить и УДАЛИТЬ данные (базу района / пользователей Keycloak)
```

## Правила

Атакуем только копии районов на своём компьютере и только на парах 9–10. Учебные пароли
(`.env.example`) перед заморозкой снимка (пара 8) замените на свои.
