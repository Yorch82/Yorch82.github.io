---
title: VH - BlackMarket
published: false
categories: [Linux]
tags: [eWPT, Fácil]
---

<img src="/assets/VH/vulnhub.png">

¡Hola!
Vamos a resolver de la máquina `BlackMarket` de dificultad "Fácil" de la plataforma [VulnHub](https://www.vulnhub.com/entry/blackmarket-1,223/).

Técnicas Vistas: 

- **Web Enumeration**
- **Creating our own dictionary with cewl**
- **FTP Brute Force - HYDRA**
- **SQLI (SQL Injection) - Error Based (Manual)**
- **Cracking Hashes**
- **Gaining access to squirrelmail**
- **Playing with quipquip - Deciphering a message**
- **Steganography challenge**
- **Abusing a backdoor previously created by an attacker [RCE]**
- **Information Leakage (User Pivoting)**
- **Abusing sudoers privilege [Privilege Escalation]**

### Preparación Entorno

* * *

Antes de iniciar la fase de enumeración y reconocimiento procederemos a crear un directorio de trabajo con el nombre `BlackMarket`. Una vez creado accedemos al directorio y con la ayuda de la función que tenemos definida en la zshrc `mkt` crearemos cuatro directorios de trabajo `nmap, content, exploits y scripts` donde almacenaremos de una manera ordenada toda la información que vayamos recopilando de la máquina en función de su naturaleza.

```bash
function mkt(){
    mkdir {nmap,content,exploits,scripts}
}
```

### Reconocimiento

* * *

Primero de todo necesitamos saber la IP de la máquina víctima que se encuentra funcionando dentro de nuestra red local. Procedemos a escanear todos los equipos de nuestra red local

```bash
❯ arp-scan -I ens33 --localnet
Interface: ens33, type: EN10MB, MAC: 00:0c:29:0b:0e:02, IPv4: 192.168.1.145
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	e4:ca:12:8c:78:a5	zte corporation
192.168.1.128	2c:f0:5d:0a:0a:f1	(Unknown)
192.168.1.134	9c:20:7b:b1:3e:47	Apple, Inc.
192.168.1.137	d0:c2:4e:53:17:09	(Unknown)
192.168.1.141	b8:bc:5b:e8:00:67	Samsung Electronics Co.,Ltd
192.168.1.143	00:0c:29:18:4a:e3	VMware, Inc.
192.168.1.138	00:55:da:56:56:66	IEEE Registration Authority
192.168.1.130	ac:67:84:98:f6:07	(Unknown)
192.168.1.132	d8:a3:5c:73:eb:02	(Unknown)
192.168.1.131	f4:34:f0:50:7e:76	(Unknown)

10 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 1.935 seconds (132.30 hosts/sec). 10 responded
```
Tras analizar la respuesta del escaneo observamos por el **OUI (Organizationally unique identifier)** 00:0c:29 que corresponde a VMWare Inc ya que la máquina víctima funciona bajo un entorno de virtualización VMWare por lo que su IP es `192.168.1.143`

Accedemos al directorio de trabajo `nmap` e iniciamos nuestra fase de reconocimiento realizando un `ping` a la IP de la máquina para comprobar que esté activa y detectamos su sistema operativo basándonos en el `ttl` de una traza **ICMP**.

```bash
❯ ping -c 1 192.168.1.143
PING 192.168.1.143 (192.168.1.143) 56(84) bytes of data.
64 bytes from 192.168.1.140: icmp_seq=1 ttl=64 time=42.3 ms

--- 192.168.1.143 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.314/42.314/42.314/0.000 ms
```
Identificamos que es una maquina **Linux** debido a su ttl (time to live) correspondiente a 64.

* TTL => 64 Linux
* TTL => 128 Windows

Continuamos con la enumeración de los **65535** puertos en la máquina.

<img src="/assets/VH/BlackMarket/nmap1.png">

Luego de identificar los puertos abiertos `OPEN`, se procede a escanear servicios y versiones que puedan estar corriendo en los puertos abiertos detectados.

<img src="/assets/VH/BlackMarket/nmap.png">

### Reconocimiento Web

* * *

Accedemos al servicio HTTP por el puerto 80 y observamos un panel de login al servicio **BlackMarket**. Probamos a ver si es vulnerable a SQLi pero no tenemos éxito 

<img src="/assets/VH/BlackMarket/web80.png">

Con la herramienta **gobuster** procedemos a enumear posibles directorios

<img src="/assets/VH/BlackMarket/gobuster.png">

Localizamos varios. nos llama la atención `/squirrelmail`. Accedemos y nos econtramos ante otro panel de login. Probamos a ver si es vulnerable a SQLi pero no tenemos éxito

<img src="/assets/VH/BlackMarket/squirrel.png">

Volviendo al panel de login de **BlackMarket** examinamos su código fuente y localizamos la primera flag

<img src="/assets/VH/BlackMarket/source.png">

Aplicamos decode y encontramos una pista

<img src="/assets/VH/BlackMarket/decode.png">

Buscando en Google a ver de qué trata la **Operación Treadstone** y la primera página que encontramos es de la película [Operation Treadstone](https://bourne.fandom.com/wiki/Operation_Treadstone). En la misma encontramos la lista del Staff de la película de la cual extraemos un diccionario de usuarios **richard, ward, alexander, albert, neil, nicky y daniel**. Utilizamos la misma web para generar un diccionario de posibles contraseñas con la herramienta **cewl** de la siguiente forma -> `cewl https://bourne.fandom.com/wiki/Operation_Treadstone -w dict.txt -d 0`

<img src="/assets/VH/BlackMarket/users.png">

### Enumeración FTP

* * *

Para poder enumerar este servicio aplicamos fuerza bruta con `hydra` con los diccionarios que hemos generado en el apartado anterior

<img src="/assets/VH/BlackMarket/hydraftp.png">

Con las credenciales obtenidas nos conectamos al servicio FTP y localizamos archivo `IMP.txt`. Nos lo descargamos para examinarlo al detalle

<img src="/assets/VH/BlackMarket/ftp.png">

El archivo contiene la segunda flag y una nueva pista

<img src="/assets/VH/BlackMarket/flag2.png">

### SQL Injection

* * *

La pista nos comenta sobre un `Vehical workshop`. Aplicando un poco de guessing probamos varias rutas posibles en el servicio web hasta que localizamos la correcta `/vworkshop` 

<img src="/assets/VH/BlackMarket/vworkshop.png">

Enumerando la web observamos que la sección `Spare Parts` es vulnerable a SQL Injection tras comprobar que la web tarda 5 segundos en responder tras aplicar inyección `http://192.168.1.143/vworkshop/sparepartsstoremore.php?sparepartid=1' and sleep(5)-- -`. Mediante `orber by` se determina que hay 7 columnas, a partir de aquí podemos ir extrayendo información de bases de datos, tablas, columnas y su contenido.

En primer lugar enumeramos las bases de datos existentes

<img src="/assets/VH/BlackMarket/databases.png">

Seguimos enumerando las tablas de la base de datos `BlackMarket`

<img src="/assets/VH/BlackMarket/blackmarket_tables.png">

Observamos una tabla `flag`. Enumeramos sus columnas para ver que datos contienen

<img src="/assets/VH/BlackMarket/blackmarket_flag_columns.png">

Seguidamente dumpeamos la infromación de las columnas `name` e `information`. Nos econtramos ante otra pista.

<img src="/assets/VH/BlackMarket/flag_data.png">

Tras la pista seguimos enumerando las columnas de la tbala `user`

<img src="/assets/VH/BlackMarket/blackmarket_user_columns.png">

Finalmente dumpeamos la información que se encuentra en `username` y `password`

<img src="/assets/VH/BlackMarket/user_data.png">

### Crack de Hashes

* * *

Obtenemos unos hashes que por longitud parecen estar encriptados en `md5`. Procedemos a desencriptarlos con la ayuda de la web [hashes.com](https://hashes.com/en/decrypt/hash)

<img src="/assets/VH/BlackMarket/hashes.png">

Obtenemos las contraseñas en texto claro de los usuarios admin, user y supplier. Podemos acceder a través del panel de login al servicio `BackMarket` inicialmente encontrado con las credenciales de `admin`. Nada más introducir credenciales obersvamos una ventana emergente con la cuarta flag y una nueva pista

<img src="/assets/VH/BlackMarket/login_backmarket.png">

Aplicamos decode a la cuarta flag pero no sacamos información relevante

<img src="/assets/VH/BlackMarket/flag4.png">

### Acceso SquirrelMail

* * *

Con la pista obtenida anteriormente logramos acceder a la cuenta de correo de SquirrelMail de Jason Bourne con las crendenciales `jbourne:?????`. Encontramos un mensaje con información encriptada y la quinta flag en base64 como las anteriores

<img src="/assets/VH/BlackMarket/jbourne_login_squirrel.png">

<img src="/assets/VH/BlackMarket/message.png">

Decodificamos quinta flag

<img src="/assets/VH/BlackMarket/flag5.png">

### Desencriptado y esteganografía

* * *

Desencriptamos el anterior mensaje con la ayuda de la web [quipquip](https://quipqiup.com/) y obtenemos el mensaje descifrado. Descubrimos un nuevo directorio `\kgbbackdoor` y una imagen `PassPass.jpg` que debe tener algo 'escondido'. Accedemos al recurso y localizamos imagen

<img src="/assets/VH/BlackMarket/crypto.png">

<img src="/assets/VH/BlackMarket/backdoor.png">

Aplicamos fuzzing con gobuster sobre el directgorio `\kgbbackdoor` y encotramos recurso `backdoor.php` que parece estar protegido con contraseña

<img src="/assets/VH/BlackMarket/gobuster_backdoor.png">

<img src="/assets/VH/BlackMarket/backdoor_php.png">

Con la utilidad `strings` lsitamos las cadenas de caracteres de más de 10 líneas que pueda tener la imagen `PassPass.jpg` y obtenemos una contraseña

<img src="/assets/VH/BlackMarket/strings.png">

La cadena está en decimal y hay que pasarla a hexadecimal y posteriormente a texto. Obtenemos la contraseña en texto claro

<img src="/assets/VH/BlackMarket/decimal_to_hex.png">

<img src="/assets/VH/BlackMarket/hex_to_text.png">

### Abusando Backdoor

* * *

Con la contraseña obtenida podemos acceder al `backdoor`. Observamos que tenemos acceso a varias herramientas para listar archivos, ejecutar comandos, etc.

<img src="/assets/VH/BlackMarket/login_backdoor.png">

Verificamos que podemos ejecutar comandos enviándonos una traza ICMP a nuestro equipo. Nos ponemos en escucha con `tcpdump` y ejecutamos pìng desde el panel del backdoor

<img src="/assets/VH/BlackMarket/send_ping.png">

<img src="/assets/VH/BlackMarket/receive_ping.png">

Sabiendo que podemos ejecutar comandos nos ponemos en escucha con `netcat` y ejecutamos onliner para entablar una reverse shell. Ganamos acceso a la máquina vícitma con el usuario `www-data`

<img src="/assets/VH/BlackMarket/revshell.png">

<img src="/assets/VH/BlackMarket/netcat.png">

### Movimiento Lateral

* * *

Listando el contenido de `/var/www/html/vworkshop/kgbbackdoor` localizamos la sexta flag

<img src="/assets/VH/BlackMarket/flag6.png">

Enumerando el directorio `home` lozalizamos un directorio oculto `.Mylife` y un archivo `.Secret`

<img src="/assets/VH/BlackMarket/secret.png">

En el contenido del archivo parace que nos revelan la contraseña de `dimitri`. Incialmente no funciona pero cambiamos `y` por `i` de DimitryHateApple y logramos migrar al usuario `dimitri` 

<img src="/assets/VH/BlackMarket/secret.png">

### Escalada de Privilegios

* * *

Listando grupos a los que pertenece el usuario `dimitri` vemos que está en el grupo `sudo` y como tenemos su contraseña podemos elevar privilegios y convertirnos en **root**

<img src="/assets/VH/BlackMarket/dimitri_sudo.png">

La última flag la tenemos en el directorio `/root`

<img src="/assets/VH/BlackMarket/pwned.png">

Hemos completado la máquina **BlackMarket** de VulnHub!! Happy Hacking!!
