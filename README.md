# Security Guardian

Plugin di sicurezza per WordPress: protezione, scansione e ripristino in un unico strumento.

## Funzionalità

- **Protezione brute force** sul login, con blocco temporaneo per IP.
- **Indurimento**: disattiva XML-RPC, blocca l'enumerazione utenti (`?author=` e REST), nasconde la versione di WordPress, disattiva l'editor file e aggiunge header di sicurezza.
- **Mini firewall applicativo (WAF)** contro SQL injection, XSS, path traversal e scansione di file sensibili.
- **Scanner del core**: confronta i file di WordPress con i checksum ufficiali e trova file modificati, mancanti o estranei; **ripristino con un clic** all'originale ufficiale.
- **Scansione euristica** di temi, plugin e cartella uploads per malware e backdoor.
- **Scansione del database**: cerca codice iniettato in articoli, opzioni e commenti, con pulizia mirata e ripristino.
- **Quarantena**: isola i file sospetti invece di cancellarli subito.
- **Autenticazione a due fattori (TOTP)** per gli utenti, con codici di backup.
- **Registro attività**, **notifiche email** e **scansione automatica pianificata**.

## Installazione

1. Scarica l'ultima release (file `.zip`) oppure clona il repository.
2. In WordPress: **Plugin → Aggiungi nuovo → Carica plugin**, seleziona lo zip e installa.
3. Attiva il plugin e apri il menu **Security Guardian**.

> Consiglio: prova prima su un sito di test o fai un backup. È software che agisce sui file.

## Requisiti

- WordPress 5.6 o superiore
- PHP 7.4 o superiore

## Avvertenze

Un plugin agisce dentro WordPress: non sostituisce la sicurezza del server, i backup, né l'aggiornamento costante di core, temi e plugin. Lo scanner euristico può dare falsi positivi: metti sempre in quarantena prima di eliminare. Dopo aver pulito un sito compromesso, cambia le password (admin, FTP, database) e le chiavi di sicurezza in `wp-config.php`.

## Licenza

GPL-2.0-or-later. Vedi il file [LICENSE](LICENSE).
