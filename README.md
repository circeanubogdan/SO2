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
