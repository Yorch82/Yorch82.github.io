---
title: HTB - Validation
published: true
categories: [Linux]
tags: [eJPT, eWPT, Fácil]
---


<img src="/assets/HTB/Validation/validation.png">


¡Hola!
Vamos a resolver de la máquina `Validation` de dificultad "Fácil" de la plataforma [HackTheBox](https://hackthebox.com/).

Técnicas Vistas: 

- **SQLI (Error Based)**
- **SQLI to RCE**
- **Information Leakage**

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
❯ ping -c 1 10.10.11.116
PING 10.10.11.116 (10.10.11.116) 56(84) bytes of data.
64 bytes from 10.10.11.116: icmp_seq=1 ttl=63 time=38.3 ms

--- 10.10.11.116 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 38.334/38.334/38.334/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 63 (Disminuye en 1 debido a que realiza un salto adicional en el entorno de HackTHeBox).

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

```java
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.116 -oG allPorts

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 62
4566/tcp open  kwtc       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```
Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

```bash
nmap -sCV -p22,80,4566,8080 10.10.11.116 -oN targeted

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn t have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Reconocimiento Web

* * *

Accedemos al servicio Web y observamos una página de registro. Rellenamos los campos y nos agregan a una lista por países

<img src="/assets/HTB/Validation/web.png">
<img src="/assets/HTB/Validation/registro.png">

Procedemos a interceptar petición con BurpSuite. Inyectamos una `'` en el campo `country` y vemos un error en respuesta, ahora sabemos que tenemos SQLI Conditional Error

<img src="/assets/HTB/Validation/burp.png">

Probando varios payloads, vemos que con `union select` logramos listar elementos de la base de datos

<img src="/assets/HTB/Validation/database.png">
<img src="/assets/HTB/Validation/databaseresponse.png">

Sabemos que la base de datos se llama `registration`, procedemos a listar tablas de esta BD

<img src="/assets/HTB/Validation/tables.png">
<img src="/assets/HTB/Validation/tablesresponse.png">

Seguimos enumerando columnas de la tabla `registration` y base de datos `registration`

<img src="/assets/HTB/Validation/columns.png">
<img src="/assets/HTB/Validation/columnsresponse.png">

Listamos contenido de columnas `username` y `userhash`

<img src="/assets/HTB/Validation/user.png">
<img src="/assets/HTB/Validation/userresponse.png">

Los datos mostrados corresponden a usuarios y hashes que hemos creado nosotros haciendo pruebas de inyección por lo que no podemos sacar mucho de aquí. Seguimos a validar si tenemos la capacidad de depositar contenido en una ruta

<img src="/assets/HTB/Validation/into.png">
<img src="/assets/HTB/Validation/intoresponse.png">

Paso siguiente tratamos de depositar una instrucción en PHP para que podamos ejecutar comandos

<img src="/assets/HTB/Validation/php.png">
<img src="/assets/HTB/Validation/phpresponse.png">

En este punto con la capacidad de RCE ejecutamos onliner para entablar reverse shell. Nos ponemos en escucha en el puerto 443

<img src="/assets/HTB/Validation/shell.png">

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.11.116] 39462
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ whoami
whoami
www-data
```

### Escalada Privilegios

* * *

Enumerando el contenido de la carpeta `/var/www/html/` vemos un archivo `config.php` y listando su contenido encontramos unas credenciales

```php
www-data@validation:/var/www/html$ ls
account.php  config.php  css  index.php  js
www-data@validation:/var/www/html$ cat config.php 
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```
Probamos a ver si hay reutilización de credenciales y logramos acceder a root

```bash
www-data@validation:/var/www/html$ su root
Password: 
root@validation:/var/www/html# whoami
root
```

### Flags

* * *

Tras una búsqueda desde la raíz localizamos las flags en sus respectivos directorios. Con el comando `cat` nos muestra el contenido.

```bash
#USER
root@validation:/# find / -name user.txt 2>/dev/null
/home/htb/user.txt
root@validation:/# cat /home/htb/user.txt
4e72ed159e5a30d65***************
```

```bash
#ROOT
root@validation:/# find / -name root.txt 2>/dev/null 
/root/root.txt
root@validation:/# cat /root/root.txt
9044af5fa347efab8***************
```

Hemos completado la máquina **Validation** de HackTheBox!! Happy Hacking!!


<img src="/assets/HTB/Validation/pwned.png">
