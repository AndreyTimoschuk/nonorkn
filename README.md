# UFW Multi-Level Blacklist Script

Скрипт для автоматической **многоуровневой** блокировки нежелательных подсетей на серверах с UFW.

---

## ⚠️ ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ

**ИСПОЛЬЗУЙТЕ ЭТОТ СКРИПТ НА СВОЙ СТРАХ И РИСК!**

**Автор не несёт никакой ответственности за:**
- Потерю доступа к серверу
- Блокировку легитимного трафика
- Проблемы с сетевым соединением
- Любые другие проблемы, возникшие в результате использования этого скрипта

**Перед использованием:**
- Убедитесь, что у вас есть альтернативный доступ к серверу (консоль хостера, IPMI, KVM)
- Протестируйте на некритичном сервере
- Добавьте свои IP-адреса в whitelist

**НИКАКИХ ГАРАНТИЙ НЕ ПРЕДОСТАВЛЯЕТСЯ.**

---

## Описание

Скрипт использует связку **ipset + UFW** для многоуровневой блокировки сетей без существенного влияния на производительность сервера.

### Два уровня блокировки:

| Уровень | ipset | Блокировка | Описание |
|---------|-------|------------|----------|
| **Dangerous** | `blacklist_dangerous` | INPUT + OUTPUT + ESTABLISHED | Ботнеты, малварь, Tor, спамеры — полная изоляция |
| **RU** | `blacklist_ru` | Только INPUT | Российские госструктуры — блок входящих, исходящие разрешены |

### Источники списков:

- **Dangerous** — [FireHOL blocklist-ipsets](https://github.com/firehol/blocklist-ipsets):
  - `spamhaus_drop.netset` — hijacked networks, professional spam/cybercrime
  - `spamhaus_edrop.netset` — extended DROP list
  - `blocklist_de.ipset` — brute force attacks (last 48h)
  - `feodo.ipset` — banking trojans (Emotet, Dridex)
  - `tor_exits.ipset` — TOR exit nodes
  - `dshield.netset` — top attacking subnets

- **RU** — [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List) — подсети российских госструктур

---

## Как это работает: ipset + iptables + UFW

### Архитектура

```
┌─────────────────────────────────────────────────────────────────┐
│                      ВХОДЯЩИЙ ПАКЕТ                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ЯДРО LINUX (netfilter)                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              ufw-before-input chain                        │  │
│  │                                                            │  │
│  │  1. WHITELIST (src) ────────────────────→ ACCEPT          │  │
│  │                                                            │  │
│  │  2. DANGEROUS (src) ────────────────────→ DROP            │  │
│  │     ↑ БЛОК ДО ESTABLISHED! Даже ответы блокируются        │  │
│  │                                                            │  │
│  │  3. ESTABLISHED,RELATED ────────────────→ ACCEPT          │  │
│  │     ↑ Только для НЕ-dangerous IP                          │  │
│  │                                                            │  │
│  │  4. RU BLACKLIST (src) ─────────────────→ DROP            │  │
│  │     ↑ Только новые входящие (исходящие разрешены)         │  │
│  │                                                            │  │
│  │  5. UFW user rules (ufw allow 22/tcp и т.д.)              │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              ufw-before-output chain                       │  │
│  │                                                            │  │
│  │  1. WHITELIST (dst) ────────────────────→ ACCEPT          │  │
│  │                                                            │  │
│  │  2. DANGEROUS (dst) ────────────────────→ DROP            │  │
│  │     ↑ Сервер НЕ МОЖЕТ подключаться к ботнетам!            │  │
│  │                                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Почему ipset, а не обычные правила iptables/UFW?

| Подход | 50,000 подсетей | Сложность поиска | RAM |
|--------|-----------------|------------------|-----|
| `ufw deny from X.X.X.X` × 50000 | 50000 правил iptables | O(n) — линейный перебор | ~2 GB |
| `ipset` + 2 правила iptables | 2 правила + hash table | **O(1)** — мгновенно | ~5 MB |

**ipset** хранит IP/подсети в хэш-таблице на уровне ядра. Проверка любого IP занимает одинаковое время независимо от размера списка.

### Порядок обработки правил (INPUT)

```
1. Whitelist ipset → ACCEPT (всегда пропускаем доверенные)
   ↓
2. Dangerous ipset → DROP (блок ДО проверки ESTABLISHED!)
   ↓
3. ESTABLISHED,RELATED → ACCEPT (ответы на НАШИ соединения)
   ↓
4. RU blacklist ipset → DROP (только новые входящие)
   ↓
5. UFW user rules (ufw allow 22/tcp и т.д.)
```

**Важно:** Dangerous блокируется ДО ESTABLISHED, поэтому даже если вы инициировали соединение к IP из dangerous списка, ответы будут заблокированы.

---

## Установка и запуск

> **Все команды выполняются от root** (`sudo su` или `sudo bash`)

### Быстрая установка + запуск (одна команда):

```bash
curl -fsSL https://raw.githubusercontent.com/AndreyTimoschuk/nonorkn/main/ufw-blacklist.sh -o /usr/local/bin/ufw-blacklist.sh && \
chmod +x /usr/local/bin/ufw-blacklist.sh && \
/usr/local/bin/ufw-blacklist.sh
```

### Или пошагово:

```bash
# 1. Скачать скрипт
curl -fsSL https://raw.githubusercontent.com/AndreyTimoschuk/nonorkn/main/ufw-blacklist.sh -o /usr/local/bin/ufw-blacklist.sh

# 2. Сделать исполняемым
chmod +x /usr/local/bin/ufw-blacklist.sh

# 3. (Опционально) Отредактировать whitelist - добавить свои IP
nano /usr/local/bin/ufw-blacklist.sh

# 4. Запустить
/usr/local/bin/ufw-blacklist.sh
```

---

## Настройка

### Whitelist (рекомендуется!)

Откройте скрипт и добавьте доверенные IP:

```bash
nano /usr/local/bin/ufw-blacklist.sh
```

```bash
WHITELIST_IPS=(
    "YOUR.HOME.IP.ADDRESS"      # Ваш домашний IP
    "YOUR.OFFICE.IP.ADDRESS"    # IP офиса
    "YOUR.VPN.SERVER.IP"        # VPN сервер
)
```

### Отключение отдельных списков

Чтобы отключить RU blacklist, закомментируйте или очистите:
```bash
URL_RU=""
```

Чтобы отключить dangerous списки, очистите массив:
```bash
URLS_DANGEROUS=()
```

---

## Автообновление (cron)

```bash
# Открыть crontab
crontab -e

# Добавить строку (запуск в 02:00 и 14:00):
0 2,14 * * * /usr/local/bin/ufw-blacklist.sh >> /var/log/ufw_blacklist_cron.log 2>&1
```

---

## Проверка работы

```bash
# Статистика ipset
ipset list -t

# Количество записей
echo "Whitelist: $(ipset list whitelist 2>/dev/null | grep -c '^[0-9]')"
echo "Dangerous: $(ipset list blacklist_dangerous 2>/dev/null | grep -c '^[0-9]')"
echo "RU: $(ipset list blacklist_ru 2>/dev/null | grep -c '^[0-9]')"

# Проверить конкретный IP
ipset test blacklist_dangerous 1.2.3.4
ipset test blacklist_ru 1.2.3.4

# Посмотреть правила iptables
iptables -L ufw-before-input -v -n --line-numbers | head -15
iptables -L ufw-before-output -v -n --line-numbers | head -10

# Посмотреть правила в UFW before.rules
grep -A15 "BEGIN IPSET" /etc/ufw/before.rules

# Логи
tail -f /var/log/ufw_blacklist.log
```

---

## Удаление

```bash
# 1. Удалить правила из UFW
sed -i '/# BEGIN IPSET BLACKLIST/,/# END IPSET BLACKLIST/d' /etc/ufw/before.rules

# 2. Перезагрузить UFW
ufw reload

# 3. Удалить ipset наборы
ipset destroy blacklist_dangerous
ipset destroy blacklist_ru
ipset destroy whitelist

# 4. Удалить systemd сервис
systemctl disable ipset-load.service
rm /etc/systemd/system/ipset-load.service

# 5. Удалить файлы
rm /usr/local/bin/ufw-blacklist.sh
rm /usr/local/bin/load-ipset-blacklist.sh
rm /etc/ipset.rules
rm /var/log/ufw_blacklist.log
```

---

## Решение проблем

### Потерял доступ к серверу

1. Подключитесь через консоль хостера (VNC/KVM/IPMI)
2. Выполните:
   ```bash
   ufw disable
   ipset flush whitelist
   ipset flush blacklist_dangerous
   ipset flush blacklist_ru
   ```

### Заблокирован нужный IP

```bash
# Проверить в каком списке IP
ipset test whitelist X.X.X.X
ipset test blacklist_dangerous X.X.X.X
ipset test blacklist_ru X.X.X.X

# Добавить в whitelist
ipset add whitelist X.X.X.X

# Сохранить
ipset save > /etc/ipset.rules
```

### Скрипт не работает после перезагрузки

```bash
# Проверить что сервис включен
systemctl status ipset-load.service

# Включить если не включен
systemctl enable ipset-load.service
```

### Нужно срочно отключить блокировку

```bash
# Временно (до перезагрузки UFW)
iptables -D ufw-before-input -m set --match-set blacklist_dangerous src -j DROP
iptables -D ufw-before-output -m set --match-set blacklist_dangerous dst -j DROP
iptables -D ufw-before-input -m set --match-set blacklist_ru src -j DROP
```

---

## Лицензия

MIT License. Делайте что хотите, но на свой страх и риск.

---

## Автор

[@AndreyTimoschuk](https://github.com/AndreyTimoschuk)
