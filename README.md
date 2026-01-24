# UFW Blacklist Script

Скрипт для автоматической блокировки нежелательных подсетей на серверах с UFW.

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

Скрипт использует связку **ipset + UFW** для блокировки тысяч подсетей без существенного влияния на производительность сервера.

### Что делает скрипт:

1. Скачивает актуальный список подсетей из [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List)
2. Создаёт ipset наборы для blacklist и whitelist
3. Интегрирует ipset с UFW через `/etc/ufw/before.rules`
4. Настраивает автозагрузку правил при перезагрузке сервера
5. Сохраняет ответные пакеты на исходящие соединения (ESTABLISHED,RELATED)

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
│  │                      iptables                              │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              ufw-before-input chain                  │  │  │
│  │  │                                                      │  │  │
│  │  │  1. ESTABLISHED,RELATED → ACCEPT (ответы на НАШИ    │  │  │
│  │  │     исходящие соединения проходят)                   │  │  │
│  │  │                                                      │  │  │
│  │  │  2. ipset whitelist → ACCEPT (доверенные IP)        │  │  │
│  │  │                        ↓                             │  │  │
│  │  │                   ┌─────────┐                        │  │  │
│  │  │                   │ ipset   │ ← O(1) lookup!        │  │  │
│  │  │                   │whitelist│   (hash table)        │  │  │
│  │  │                   └─────────┘                        │  │  │
│  │  │                                                      │  │  │
│  │  │  3. ipset blacklist → DROP (блокируем)              │  │  │
│  │  │                        ↓                             │  │  │
│  │  │                   ┌─────────┐                        │  │  │
│  │  │                   │ ipset   │ ← O(1) lookup!        │  │  │
│  │  │                   │blacklist│   (3000+ подсетей)    │  │  │
│  │  │                   └─────────┘                        │  │  │
│  │  │                                                      │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                          │                                 │  │
│  │                          ▼                                 │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              ufw-user-input chain                    │  │  │
│  │  │         (ваши правила: ufw allow 22/tcp и т.д.)     │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                        ПРИЛОЖЕНИЕ
```

### Почему ipset, а не обычные правила iptables/UFW?

| Подход | 3000 подсетей | Сложность поиска | RAM |
|--------|---------------|------------------|-----|
| `ufw deny from X.X.X.X` × 3000 | 3000 правил iptables | O(n) — линейный перебор | ~150 MB |
| `ipset` + 1 правило iptables | 1 правило + hash table | **O(1)** — мгновенно | ~1 MB |

**ipset** хранит IP/подсети в хэш-таблице на уровне ядра. Проверка любого IP занимает одинаковое время независимо от размера списка.

### Компоненты

#### 1. ipset (ядро Linux)
```bash
# Создание набора для подсетей
ipset create blacklist hash:net maxelem 131072

# Добавление подсети
ipset add blacklist 192.168.0.0/24

# Проверка IP
ipset test blacklist 192.168.0.1
# Warning: 192.168.0.1 is in set blacklist.
```

#### 2. iptables (netfilter)
```bash
# Одно правило блокирует ВСЕ подсети из ipset
iptables -A INPUT -m set --match-set blacklist src -j DROP
```

#### 3. UFW (надстройка над iptables)
UFW управляет iptables через конфигурационные файлы:
- `/etc/ufw/before.rules` — правила ДО пользовательских (сюда мы добавляем ipset)
- `/etc/ufw/user.rules` — ваши правила (`ufw allow 22`)
- `/etc/ufw/after.rules` — правила ПОСЛЕ пользовательских

Скрипт добавляет правила ipset в `before.rules`, поэтому они обрабатываются **первыми**.

### Порядок обработки правил

```
1. ESTABLISHED,RELATED → ACCEPT
   ↓ (если НЕ установленное соединение)
2. Whitelist ipset → ACCEPT  
   ↓ (если IP НЕ в whitelist)
3. Blacklist ipset → DROP
   ↓ (если IP НЕ в blacklist)
4. Обычные UFW правила (ufw allow 22/tcp и т.д.)
```

**Важно:** правило `ESTABLISHED,RELATED` позволяет получать ответы на ваши исходящие соединения, даже если сервер находится в blacklist. Например, вы можете подключаться к API или скачивать файлы с заблокированных IP.

### Источник blacklist:

[C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List) — подсети российских государственных структур и связанных с ними сетей. Обновляется ежедневно.

---

## Установка

### Быстрая установка (одна команда):

```bash
curl -fsSL https://raw.githubusercontent.com/AndreyTimoschuk/nonorkn/main/ufw-blacklist.sh -o /usr/local/bin/ufw-blacklist.sh && \
chmod +x /usr/local/bin/ufw-blacklist.sh
```

### Или пошагово:

```bash
# 1. Скачать скрипт
curl -fsSL https://raw.githubusercontent.com/AndreyTimoschuk/nonorkn/main/ufw-blacklist.sh -o /usr/local/bin/ufw-blacklist.sh

# 2. Сделать исполняемым
chmod +x /usr/local/bin/ufw-blacklist.sh

# 3. (ВАЖНО!) Отредактировать whitelist - добавить свои IP
nano /usr/local/bin/ufw-blacklist.sh
```

---

## Настройка Whitelist

**Перед первым запуском** откройте скрипт и добавьте свои IP-адреса в массив `WHITELIST_IPS`:

```bash
nano /usr/local/bin/ufw-blacklist.sh
```

Найдите секцию:

```bash
WHITELIST_IPS=(
    # Example: "1.2.3.4"
    # Example: "10.0.0.0/8"
)
```

Добавьте свои IP:

```bash
WHITELIST_IPS=(
    "YOUR.HOME.IP.ADDRESS"      # Ваш домашний IP
    "YOUR.OFFICE.IP.ADDRESS"    # IP офиса
    "YOUR.VPN.SERVER.IP"        # VPN сервер
)
```

---

## Использование

### Первый запуск:

```bash
# Убедитесь что UFW включен
ufw enable

# Запустите скрипт
/usr/local/bin/ufw-blacklist.sh
```

### Добавить в cron (автообновление каждые 12 часов):

```bash
# Открыть crontab
crontab -e

# Добавить строку:
0 2,14 * * * /usr/local/bin/ufw-blacklist.sh >> /var/log/ufw_blacklist_cron.log 2>&1
```

Это будет запускать скрипт в 02:00 и 14:00 каждый день.

---

## Проверка работы

```bash
# Статистика ipset
ipset list -t

# Проверить конкретный IP в blacklist
ipset test blacklist 1.2.3.4

# Посмотреть правила в UFW
grep -A5 "BEGIN IPSET" /etc/ufw/before.rules

# Посмотреть логи
tail -f /var/log/ufw_blacklist.log

# Количество заблокированных подсетей
ipset list blacklist | grep -c "^[0-9]"
```

---

## Удаление

Если нужно удалить скрипт и все правила:

```bash
# 1. Удалить правила из UFW
sed -i '/# BEGIN IPSET BLACKLIST/,/# END IPSET BLACKLIST/d' /etc/ufw/before.rules

# 2. Перезагрузить UFW
ufw reload

# 3. Удалить ipset наборы
ipset destroy blacklist
ipset destroy whitelist

# 4. Удалить systemd сервис
systemctl disable ipset-load.service
rm /etc/systemd/system/ipset-load.service

# 5. Удалить файлы
rm /usr/local/bin/ufw-blacklist.sh
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
   ipset destroy blacklist
   ipset destroy whitelist
   ```

### Заблокирован нужный IP

```bash
# Проверить в каком списке IP
ipset test blacklist X.X.X.X
ipset test whitelist X.X.X.X

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

---

## Лицензия

MIT License. Делайте что хотите, но на свой страх и риск.

---

## Автор

[@AndreyTimoschuk](https://github.com/AndreyTimoschuk)
