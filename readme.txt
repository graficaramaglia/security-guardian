=== Security Guardian ===
Contributors: giovanni
Tags: security, firewall, malware, scanner, brute force
Requires at least: 5.6
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.1.1
License: GPLv2 or later

Protezione, scansione e ripristino per WordPress.

== Descrizione ==

Security Guardian mette insieme in un unico plugin:

* Protezione brute force sul login (blocco per IP dopo N tentativi).
* Indurimento: disattiva XML-RPC, blocca l'enumerazione utenti, nasconde la versione di WordPress, disattiva l'editor file e aggiunge header di sicurezza.
* Mini firewall applicativo contro SQL injection, XSS, path traversal e scansione di file sensibili.
* Scanner del core: confronta i file di WordPress con i checksum ufficiali e trova file modificati, mancanti o estranei.
* Ripristino con un clic dei file del core all'originale ufficiale.
* Scansione euristica di temi, plugin e uploads per trovare malware e backdoor.
* Quarantena: isola i file sospetti invece di cancellarli subito, con ripristino o eliminazione definitiva.
* Scansione del database: cerca script e codice iniettato in articoli, opzioni e commenti, con pulizia mirata e ripristino.
* Autenticazione a due fattori (TOTP) per gli utenti, con codici di backup.
* Registro attività e notifiche email.
* Scansione automatica pianificata (ogni ora / giornaliera / due volte al giorno).

== Installazione ==

1. Carica la cartella `security-guardian` in `/wp-content/plugins/`, oppure installa lo zip dal pannello Plugin > Aggiungi nuovo > Carica plugin.
2. Attiva il plugin.
3. Vai nel menu "Security Guardian" e avvia la prima scansione.

== Avvertenze ==

* Un plugin agisce dentro WordPress: non sostituisce la sicurezza del server, i backup, né l'aggiornamento di core, temi e plugin.
* Lo scanner euristico può dare falsi positivi: metti sempre in quarantena prima di eliminare.
* Dopo aver pulito un sito compromesso, cambia le password (admin, FTP, database) e le chiavi di sicurezza in wp-config.php.

== Changelog ==

= 1.1.1 =
* Scanner molto più preciso: le firme euristiche ora richiedono combinazioni tipiche del malware, eliminando i falsi positivi su librerie di crittografia, polyfill e file minificati.
* Lo scanner non analizza più la propria cartella (niente auto-segnalazione).
* I file PHP "guardiano" innocui nella cartella uploads (index.php vuoti, blocchi ABSPATH) non vengono più segnalati.
* Allineati i numeri di versione.

= 1.1.0 =
* Nuovo: scansione del database (articoli, opzioni, commenti) con pulizia e ripristino.
* Nuovo: autenticazione a due fattori TOTP con codici di backup.

= 1.0.0 =
* Prima versione: protezione, scanner core, scanner euristico, quarantena e ripristino.
