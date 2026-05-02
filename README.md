# VpnMihomoCheker

Автоматическая проверка VPN ключей из открытых подписок через Mihomo.  
Обновляется каждые 3 часа через GitHub Actions.

## Как работает

```
subscriptions.txt
      ↓
1. Сбор ключей (параллельно, 20 потоков)
      ↓
2. Дедупликация по (host, port, uuid/password)
      ↓
3. TCP пре-фильтр (300 параллельных, 2с таймаут)
      ↓
4. Mihomo batch проверка (listeners режим)
   → один процесс = 50 прокси одновременно
      ↓
5. GeoIP по exit IP (ip-api.com)
      ↓
6. Сохранение результатов
```

## Результаты

| Файл | Описание |
|------|----------|
| `results/all_working.txt` | Все рабочие ключи (raw) |
| `results/all_working_sub.txt` | base64 подписка (все страны) |
| `results/countries/RU.txt` | Подписка только Россия |
| `results/countries/DE.txt` | Подписка только Германия |
| `results/stats.json` | Статистика последней проверки |

## Формат ключей

```
vless://uuid@host:port?...#🇷🇺 Russia | Aeza 1
vless://uuid@host:port?...#🇩🇪 Germany | Hetzner 1
trojan://pass@host:port?...#🇳🇱 Netherlands | DO 1
```

## Запуск локально

```bash
pip install -r requirements.txt
python checker.py
```

### Параметры

```
--workers     10    # параллельных Mihomo процессов
--batch       50    # прокси на один процесс
--timeout     3     # SOCKS5 timeout (сек)
--tcp-timeout 2     # TCP пре-фильтр timeout (сек)
--max-ping    1500  # макс. пинг (0 = без фильтра)
--skip-tcp          # пропустить TCP фильтр
--no-install        # не скачивать Mihomo автоматически
```

## Добавить подписку

Открой `subscriptions.txt` и добавь URL (один на строку):

```
https://example.com/subscription
# Это комментарий — игнорируется
```
