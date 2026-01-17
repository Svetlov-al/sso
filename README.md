# SSO сервис

gRPC сервис со SQLite и SQL миграциями.

## Требования

- Go 1.25+

## Структура проекта

- `cmd/sso` - точка входа gRPC сервера
- `cmd/migrator` - запуск миграций
- `migrations/` - SQL миграции
- `config/local.yaml` - локальная конфигурация
- `storage/` - файл базы SQLite

## Конфигурация

Отредактируйте `config/local.yaml`. Обязательные поля:

- `storage_path` - путь к файлу SQLite
- `grpc.port` - порт gRPC
- `token_ttl` - время жизни токена (формат длительности Go, например `1h`)

## Запуск миграций

```sh
go run ./cmd/migrator --storage-path=./storage/sso.db --migrations-path=./migrations
```

## Запуск сервера

```sh
go run ./cmd/sso
```
