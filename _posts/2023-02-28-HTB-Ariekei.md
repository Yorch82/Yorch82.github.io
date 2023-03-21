---
title: HTB - Ariekei
published: false
categories: [Linux]
tags: [eWPT, OSWE, eCPPTv2, eCPTXv2, Insane]
---


<img src="/assets/HTB/Ariekei/ariekei.png">


¡Hola!
Vamos a resolver de la máquina `Ariekei` de dificultad "Insane" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **ImageTragick Exploitation (Specially designed '.mvg' file)**
- **ShellShock Attack (WAF Bypassing)**
- **Abusing Docker privilege**
- **PIVOTING**


### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Ariekei`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.65
PING 10.10.10.65 (10.10.10.65) 56(84) bytes of data.
64 bytes from 10.10.10.65: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.65 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.65 -oG allPorts

PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
1022/tcp open  exp2
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
nmap -sCV -p22,443,1022 10.10.10.65 -oN targeted

PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a75bae6593cefbddf96a7fde5067f6ec (RSA)
|   256 642ca65e96cafb10058236baf0c992ef (ECDSA)
|_  256 519f8764be99352a80a6a225ebe0959f (ED25519)
443/tcp  open  ssl/https nginx/1.10.2
| ssl-cert: Subject: stateOrProvinceName=Texas/countryName=US
| Subject Alternative Name: DNS:calvin.ariekei.htb, DNS:beehive.ariekei.htb
| Not valid before: 2017-09-24T01:37:05
|_Not valid after:  2045-02-08T01:37:05
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_http-server-header: nginx/1.10.2
1022/tcp open  ssh       OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 9833f6b64c18f5806685470cf6b7907e (DSA)
|   2048 78400d1c79a145d428753536ed424f2d (RSA)
|   256 45a67196df62b554666b917b746adbb7 (ECDSA)
|_  256 ad8d4d698e7afdd8cd6ec14f6f81b41f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Agregamos `ariekei.htb`, `calvin.ariekei.htb` y `beehive.ariekei.htb` a nuestro `/etc/hosts`

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb https://beehive.ariekei.htb
https://beehive.ariekei.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.10.2], IP[10.10.10.65], Title[Site Maintenance], UncommonHeaders[x-ariekei-waf], nginx[1.10.2]
❯ whatweb https://calvin.ariekei.htb
https://calvin.ariekei.htb [404 Not Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.10.2], IP[10.10.10.65], Title[404 Not Found], nginx[1.10.2]
```

Accedemos a la web bajo el dominio `beehive.ariekei.htb` y vemos que está en desarrollo. Ninguna funcionalidad implementada

<img src="/assets/HTB/Ariekei/web.png">

Seguimos enumerando directorios con la herramienta `gobuster`. Encontramos una entrada `blog`

```bash
❯ gobuster dir -u https://beehive.ariekei.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 20 -k -add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://beehive.ariekei.htb/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/28 16:33:23 Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 301) [Size: 325] [--> http://beehive.ariekei.htb/blog/]
/cgi-bin/             (Status: 403) [Size: 295]
/development.log      (Status: 403) [Size: 1618]                                      
/global.asa           (Status: 403) [Size: 1618]                                      
/global.asax          (Status: 403) [Size: 1618]                                      
/index.html           (Status: 200) [Size: 487]                                       
/main.mdb             (Status: 403) [Size: 1618]                                      
/php.ini              (Status: 403) [Size: 1618]                                      
/production.log       (Status: 403) [Size: 1618]                                      
/server-status        (Status: 403) [Size: 300]                                       
/spamlog.log          (Status: 403) [Size: 1618]                                      
/thumbs.db            (Status: 403) [Size: 1618]                                      
/web.config           (Status: 403) [Size: 1618]    
```
<img src="/assets/HTB/Ariekei/blog.png">

A pesar de haber varias entradas pinches a la que pinches nos dirige a la misma página. Vamos a crear un diccionario personalizado con `Cewl`

```bash
❯ cewl -w diccionario.txt https://beehive.ariekei.htb/blog/post.html
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ cat diccionario.txt | wc -l
431
```



### Explotación Tomcat

* * *



### Movimiento Lateral

* * *



### Escalada Privilegios

* * *



Hemos completado la máquina **Ariekei** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Ariekei/pwned.png">