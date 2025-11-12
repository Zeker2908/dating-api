# Dating API Microservices

![Статус проекта](https://img.shields.io/badge/status-30%25%20Complete-yellow)

Распределённое микросервисное приложение, обеспечивающее аутентификацию, авторизацию и уведомления для платформы знакомств. Проект находится в **активной разработке (25%)**.

---

## 📝 Описание

Репозиторий содержит набор микросервисов на Spring Boot для современного dating-приложения. Включает:

* **Auth Service**: регистрация пользователей, подтверждение email, управление паролями, аутентификация на основе JWT
* **API Gateway**: центральная точка входа, валидация JWT, обогащение заголовков
* **Notification Service**: отправка email через Kafka с шаблонами Thymeleaf
* **Discovery**: Eureka Server
* **Инфраструктура**: PostgreSQL, Redis, Kafka + Zookeeper через Docker Compose

---

## 🔧 Технологический стек

* **Язык & фреймворки**: Java 21, Spring Boot 3.4.4, Spring Cloud 2024.0.1
* **API & Gateway**: Spring Cloud Gateway, Spring Security + OAuth2, JWT (EC‑256)
* **Сервис-дискавери & конфигурация**: Eureka (Netflix), Spring Cloud Config Server
* **Хранилища данных**:

    * PostgreSQL через Spring Data JPA
    * Redis (Jedis) для хранения refresh-токенов и кэша
* **Месседжинг**: Apache Kafka (Spring Kafka)
* **Миграции схемы**: Liquibase
* **Генерация кода & утилиты**: MapStruct 1.6.3, Lombok 1.18.36, Guava
* **Документация**: Springdoc OpenAPI (Swagger UI), Javadoc
* **Шаблонные письма**: Thymeleaf

---

## 🚀 Начало работы

> ⚠️ **Внимание**: на данный момент полностью реализованы только инфраструктура и сервисы Auth/Notification.

### Требования

* Java 21
* Maven 3.8+
* Docker & Docker Compose
* Переменные окружения:

  ```bash
  export CLIENT_ID=<CLIEND_ID для Google OA2uth>
  export CLIENT_SECRET=<CLIENT_SECRET для Google OA2uth>
  export ADMIN_USERNAME=<admin_email>
  export MAIL_USERNAME=<MAIL_USERNAME для smtp>
  export MAIL_PASSWORD=<MAIL_PASSWORD для smtp>
  
  ```

### Запуск инфраструктуры
```bash
# Генерация приватных ключей
mkdir secrets/keys
cd secrets/keys
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem
openssl pkcs8 -topk8 -nocrypt -in ec-private.pem -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

```bash
# из корня репозитория
docker compose up --build
```

Запустятся:

* Eureka Server (`localhost:8761`)
* PostgreSQL (`localhost:5432`)
* Redis (6379 & 6380)
* Kafka & Zookeeper

---

## ✅ Реализовано

### Auth Service

* **Регистрация** с подтверждением email (через Kafka ➔ Notification Service)
* **Аутентификация**:

    * Access & Refresh токены (EC‑256 JWT)
    * Обновление refresh-токенов, хранение в Redis
* **Управление паролями**:

    * Сброс пароля (авторизованный и по email)
    * Изменение пароля с выходом из всех устройств
    * История паролей (не разрешает повторение последних)
* **Логаут** (текущая сессия и все сессии)
* **Операции над аккаунтом**

  * Получение данных об аккаунте
  * Изменение пароля с выходом из всех устройств
  * Удалить аккаунт
* **Документация**: Swagger UI & Javadoc

### API Gateway

* Валидация JWT с помощью кастомного фильтра
* Обогащение заголовков (userId, email, роль)
* Маршрутизация в защищённые сервисы

### Notification Service

* Слушатель Kafka для событий пользователей (регистрация, изменение пароля и т.д.)
* Отправка email через SMTP с Thymeleaf-шаблонами

### Common Module

* Общие DTO, заголовки API, обработка ошибок, утилиты

---

## 🚧 Дорожная карта (Roadmap)

* **CI/CD**: GitHub Actions / GitLab CI + Docker + публикация в registry
* **Profile Service**: микросервис для профилей пользователей (фото, био, предпочтения)
* **Matching Service**: логика подбора и рекомендации
* **Geo‑локация**: PostGIS для поиска рядом
* **Админ-панель**: управление и мониторинг через UI
* Отказ от Spring Config Server в пользу Vault или Kubernetes Config

Будем рады вашему вкладу и идеям!

---

## 🤝 Вклад в проект

1. Форкните репозиторий
2. Создайте ветку фичи: `git checkout -b feature/YourFeature`
3. Сделайте коммит: `git commit -m "Добавил фичу"`
4. Запушьте изменения: `git push origin feature/YourFeature`
5. Откройте Pull Request

Пожалуйста, соблюдайте существующий стиль кода и добавляйте тесты.

---

## 📞 Контакты

Maintainer: **Ваше Имя** – \[[mud.runner@bk.ru](mailto:mud.runner@bk.ru)]

Лицензия: [GPL-3.0](LICENSE)
