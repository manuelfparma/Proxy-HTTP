# HTTP/1.1 Proxy Server
## Protocolos de Comunicación - 1º cuatrimestre
### Trabajo Práctico Especial
#### Instituto Tecnológico de Buenos Aires

------------------------------------------------------------
## Autores

* **Serpe, Octavio Javer** - Legajo 60076
* **Rodríguez, Manuel Joaquín** - Legajo 60258
* **Arca, Gonzalo** - Legajo 60303
* **Parma, Manuel Félix** - Legajo 60425

------------------------------------------------------------

## Ubicación de material

El código fuente se encuentra dentro de la carpeta `src`

------------------------------------------------------------

## Dependencias

* make
* Compilador de C (conforme con estándares C11 y POSIX.1-2001)
* Librerías criptográficas de OpenSSL

------------------------------------------------------------

## Cómo compilar

Situado sobre la carpeta raíz del proyecto, ejecutar

    $ make all

------------------------------------------------------------

## Ubicación de artefactos generados

Luego de compilar, se general los ejecutables `httpd` y `httpdctl` en la carpeta raíz del proyecto.

------------------------------------------------------------

## Cómo ejecutar proxy HTTP/1.1
Para ejecutar el servidor proxy de HTTP/1.1, ejecutar

    $ ./httpd

### Argumentos de línea de comando

- `--doh-ip dirección-doh`
    - Establece   la   dirección   del  servidor  DoH.   Por  defecto `127.0.0.1`.

- `--doh-port port`
    - Establece el puerto del servidor DoH.  Por defecto `8053`.

- `--doh-host hostname`
    - Establece el valor del header Host.  Por defecto `localhost`.

- `--doh-path path`
    - Establece el path del request DoH.  por defecto `/getnsrecord`.

- `--doh-query query`
    - Establece el query string si el request DoH utiliza el método Doh por defecto `?dns=`.

- `-h`
    - Imprime la ayuda y termina.

- `-N`     
    - Deshabilita los passwords dissectors.

- `-l dirección-http`
    - Establece  la  dirección  donde  servirá  el proxy HTTP. Por defecto escucha en todas las interfaces.

- `-L dirección-de-management`
    - Establece la direcciA3n donde servirá el  servicio  de  management. Por defecto escucha únicamente en `loopback`.

- `-o puerto-de-management`
    - Puerto  donde  se  encuentra  el  servidor  de  management.  Por
defecto el valor es `9090`.

- `-p puerto-local`
    - Puerto TCP donde escucharAi por conexiones entrantes HTTP. Por defecto el valor es `8080`.

- `-v`
    - Imprime información sobre la versión y termina.
  
------------------------------------------------------------

## Cómo ejecutar cliente de monitoreo

Para ejecutar el cliente de monitoreo y configuración de proxy, ejecutar

    $ ./httpdctl

### Argumentos de línea de comando
- `-h`
    - Imprime el manual y finaliza.

- `-v`
    - Imprime la versión del programa `./httpdctl` y finaliza.

- `-p puerto-proxy`
    - Puerto UDP donde el servidor PCAMP escucha. Por defecto toma el valor `9090`.

- `-l dirección-proxy`
    - Establece la dirección donde el servidor PCAMP escucha. Por defecto toma el valor `127.0.0.1`.