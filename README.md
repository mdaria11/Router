Moldovan Daria - 324CC

TEMA1 PCOM - ROUTER 

Cerinte implementate: Procesul de dirijare(Protocol IP), Protocol ICMP

   Inainte de toate am parsat cele doua tabele ARP si cea de rutare si am salvat in 
"broadcast_mac_address" adresa de broadcast. Cand primim un pachet ne uitam la primul
header de Ethernet. Verificam ca adresa MAC destinatie din header coincide cu adresa
MAC a interfetei de pe care a venit (adica verificam daca a ajuns la destinatia buna) sau
daca are adresa MAC de broadcast care e destinat tuturor routerelor. In cazul in care
nu este de broadcast si nici destinat routerului, aruncam pachetul.
    In cazul in care pachetul a ajuns la destinatia buna, trebuie sa verificam ce fel de
pachet este; verificam ether_type-ul din headerul ethernet si aici putem avea 2 cazuri: IP
sau ARP. Cum nu am implementat ARP-ul, o sa trecem direct la protocolul IP: prima data
trebuie sa verificam daca nu cumva pachetul este un pachet destinat routerului, in cazul
nostru daca nu este cumva un echo-request. Deci luam adresa IP a interfetei de pe care a venit
pachetul si vedem daca coincide cu adresa destinatie din headerul IP. Daca cele doua sunt egale,
inseamna ca avem un mesaj ICMP de echo-request:

    Cum cele doua mesaje (echo-request si echo-reply) sunt aproape identice, am pastrat
mesajul initial si am schimbat doar campurile necesare, adica in headerul IP am inversat
adresele de sursa si destinatie intre ele si am refacut checksum. Pentru headerul ICMP
am pus 0 ca type si am refacut checksum. Cautam cea mai buna ruta ca sa aflam next-hop-ul
si cele doua adrese MAC destinatie(din tabelul ARP) si sursa (aplicam functia
get_interface_mac pentru interfata pe care trebuie sa trimitem pachetul), pe care le punem
in headerul Ethernet. Dupa trimitem pachetul pe interfata corespunzatoare.

    In cazul in care destinatia nu e routerul, verificam checksum cu functia respectiva care
intoarce 0 daca este in regula; daca avem altceva inseamna ca pachetul este corupt si-l aruncam.
Mai departe trebuie sa verificam TTL-ul sa fie mai mare decat 1; in cazul in care este 1 sau 0
trebuie sa-l aruncam si sa trimitem inapoi sursei initiale un mesaj ICMP de "TIME EXCEEDED":  

    Facem un pachet nou cu cele 3 headere de Ethernet, IP si ICMP plus cei 64 de octeti
din pachetul vechi. Completam campurile din headerul IP: adresa sursa va fi adresa IP a
interfetei de pe care vom trimite pachetul si adresa destinatie va fi vechea adresa sursa, 
protocolul il setam pe 1 (ICMP) si restul campurilor le completam cu valorile standard ale 
unui pachet de tip "TIME EXCEEDED". Completam si campurile headerului ICMP cu type-ul si 
code-ul corespunzatoare (11 si 0), calculam checksum-ul si la final copiem cei 64 de octeti 
din datele pachetului vechi. Dupa cautam in tabela de routare next-hop-ul, luam adresa MAC a
 interfetei de pe care o sa trimitem pachetul pe care o trecem ca adresa sursa in headerul 
ethernet si cautam si adresa MAC a next-hopului in tabela de ARP pe care o trecem in adresa 
destinatie din headerul ethernet, dupa trimitem pachetul pe interfata corespunzatoare.

    In cazul in care TTL-ul este mai mare ca 1, trebuie doar sa decrementam TTL-ul. Ca sa cautam
next-hop pentru pachet, trecem liniar prin tabela de rutare si verificam ca network id/prefixul
sa coincida cu prefixul din adresa noastra destinatie (aplicam AND pe adresa noastra cu masca
retelei respective ca sa scoatem bitii corespunzatori adresei retelei din adresa noastra;
daca am gasit un match inseamna ca am gasit reteaua pe care trebuie sa trimitem pachetul mai 
departe si luam din tabel adresa IP a urmatorului hop + interfata de pe care trebuie
sa trimitem pachetul; in cazul in care mai gasim un match, vedem care are masca mai mare).
In cazul in care nu am gasit niciun match trebuie sa trimitem un mesaj ICMP de "DESTINATION 
UNREACHABLE" (este identic cu mesajul ICMP de "TIME EXCEEDED" cu singura diferenta ca avem
alt numar la campul type (3) din headerul ICMP). In cazul in care am gasit o ruta, actualizam
checksum-ul din headerul IP cu functia respectiva si rescriem adresele MAC din headerul de
Ethernet: adresa MAC sursa va fi adresa MAC a interfetei de pe care vom trimite pachetul
si pentru adresa MAC destinatie punem adresa MAC a next-hopului. Pentru ca noi stim adresa IP 
a next-hop-ului, luam direct din tabela statica de ARP adresa MAC al acestuia. Dupa trimitem 
pachetul mai departe pe interfata corespunzatoare.
