# SO2
Sisteme de Operare 2 - UPB 2021:
https://linux-kernel-labs.github.io/refs/heads/master/



## `c_cpp_properties.json`
Fisierul contine setarile pentru *VS Code* cu care *intelliSense* functioneaza
(destul de) corect.



## Laboratoare
### Lab1 - Module de kernel
Introducere in infrastructura de laborator si in dezvoltarea de module de
kernel.


### Lab2 - API-ul de liste din Kernel
Se aplica urmatoarele concepte in dezvoltarea modulelor de kernel:
- alocarea si eliberarea memoriei
- utilizarea listelor din Kernel
- utilizarea unor primitive de sincroniozare (`spinlock_t` si `rwlock_t`)


### Lab 3 - Driver dispozitiv caracter
Se implementeaza un driver pentru un dispozitiv de tip caracter,
respectiv apelurile `open`, `read`, `write`, `close` si `ioctl`.


### Lab 4 - Intreruperi
Se implementeaza un keylogger care retine tastele apaste intr-un buffer. La
fieca apasare, se declanseaza o intrerupere al carei handler salveaza tasta. Se
foloseste registrul de date controllerului **i8042**, in care sunt scrise coduri
care indica tastele apasate.

Continutul bufferului poate fi citit sau sters accesand fisierul `/dev/kbd`.


### Lab 5 - Actiuni amanabile
Se creaza un dispozitiv caracter controlabil din user space prin `ioctl()`, care
in functie de comenzile primite (catre `/dev/deferred`) realizeaza o serie de
apeluri (mai mult sau mai putin blocante) sau seteaza timere pentru a demonstra
mecanismele *deferred work*


### Lab 6 - Maparea memoriei
Labul presupune 2 module care implementeaza apelul `mmap()`, precum si
operatiile de citire si scriere din si in memoria mapata cu `mmap`. Cele 2
module difera prin faptul ca unul aloca memoria continuu d.p.d.v fizic, cu
`kmalloc()`, pe cand celalalt nu, folosind `vmalloc()`.


### Lab 7 - Managementul memoriei
O relativa continuare a labului trecut, se implementeaza un dispozitiv bloc
"virtual", care tine datele in *RAM*.



## Teme
### Tema 0 - API-ul de liste din Kernel
Se implementeaza un modul de kernel care prin scrieri catre
`/proc/list/management`, retine si modifica o lista interna. Comenzile posibile
sunt:
- `addf <str>` - adauga `<str>` la prima pozitie din lista
- `adde <str>` - adauga `<str>` la ultima pozitie din lista
- `delf <str>` - sterge prima aparitie a sirului `<str>` din lista
- `dela <str>` - sterge toate aparitiile sirului `<str>` in lista

Lista poate fi vizualizata, cate un string pe linie, citind din fisierul
`/proc/list/preview`.


### Tema 1 - Kretprobes
Se folosesc Kretprobes pentru a monitoriza urmatoarele functii apelate de
procesele din Kernel:
- `kmalloc`
- `kfree`
- `mutex_lock_nested`
- `mutex_unlock`
- `schedule`
- `up`
- `down_interruptible`

Se numara apelurile functiilor de mai sus, iar, pentru cele ce aloca sau
dealoca memorie, se si contorizeaza memoria alocata, respectiv eliberata.

Prin apeluri de `ioctl()` din user space pe `/dev/tracer`, se pot adauga sau
scoate de sub observatie anumite procese. Statisticile colectate prin probele
de mai sus pot fi vazute citind din `/proc/tracer`.


### Tema 2 - Driver UART
Practic PM 2.0. Se implementeaza un driver care stie sa comunice printr-un
port serial UART16550. Poate sa comunice fie cu un singur port (`COM1` sau
`COM2`), fie prin amandoua. Expune operatiile blocante de `read` si `write`,
iar bufferele interne sunt implementate folosind `kfifo`-uri.

Destul de jegoasa. Multumiri speciale @[Adina](https://github.com/adinasm), care
s-a ocupat de partea de registre si de frecat datasheetul.
