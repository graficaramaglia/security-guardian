=== Security Guardian ===
Contributors: giovanni
Tags: security, firewall, malware, scanner, brute force
Requires at least: 5.6
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 2.1.0
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

= 2.1.0 =
* Nuovo: il firewall esclude automaticamente i webhook dei gateway di pagamento (PayPal, Stripe, Klarna e altri via WooCommerce), così le conferme di pagamento non rischiano mai di essere bloccate.
* Nuovo campo in Impostazioni per aggiungere percorsi personalizzati da escludere dal firewall. L'esclusione controlla solo il path dell'URL, non i parametri, così non si può usare per aggirare il firewall.

= 2.0.3 =
* La scansione del database non controlla più le revisioni (copie storiche dei contenuti): erano solo rumore, duplicavano le segnalazioni della versione vera.

= 2.0.2 =
* Scansione database più chiara sui post: distingue articoli e pagine dai contenuti creati dai plugin (es. snippet di codice CSS/JS). Questi ultimi mostrano il tipo di contenuto, criticità Bassa e un avviso a non "pulirli" (rimuoverebbe il codice del plugin).

= 2.0.1 =
* La scansione del database non controlla più i transient di WordPress (_transient_*, _site_transient_*): sono cache interne che si rigenerano da sole e contengono spesso HTML legittimo, causando falsi positivi come _site_transient_wp_plugin_dependencies_plugin_data.

= 2.0.0 =
* Nuovo: scelta dei ruoli a cui si applica la 2FA (es. solo Amministratore ed Editore, non Cliente o Sottoscrittore). In Impostazioni, sezione Autenticazione a due fattori.
* Gli utenti con ruoli non selezionati non vedono la configurazione 2FA e non la ricevono al login.

= 1.2.6 =
* Corretto bug importante nell'attivazione della 2FA: il pulsante "Annulla" creava un modulo annidato che faceva partire per errore la disattivazione quando si premeva "Attiva 2FA", lasciando la pagina sempre su "Configura". Ora l'attivazione va a buon fine al primo colpo.
* Registro più chiaro: "configurazione annullata" distinta dalla disattivazione, e nome utente al posto del solo ID.

= 1.2.5 =
* Risolto l'avviso di aggiornamento che ricompariva dopo un aggiornamento riuscito (sembrava servisse aggiornare due volte). Ora la versione installata viene letta dal file su disco, così l'avviso sparisce al primo aggiornamento.

= 1.2.4 =
* Meno falsi positivi in uploads: i file "guardiano" index.php (es. WPForms) e quelli che negano l'accesso (header/exit) non vengono più segnalati. In compenso, un vero backdoor in uploads viene rilevato anche se chiamato index.php.

= 1.2.3 =
* Rimossa la firma "scrittura di codice PHP in un file", che segnalava come sospetti molti plugin legittimi (cache, migrazioni, generatori di configurazione). I dropper reali restano coperti dalle altre firme.

= 1.2.2 =
* Meno falsi positivi sul core: i file innocui e legati alla lingua (readme.html, license.txt, wp-config-sample.php, wp-includes/version.php e licenze/readme tradotti) non vengono più segnalati come modificati. Utile soprattutto sui siti in italiano.
* La barra "Metti in quarantena i selezionati" e il "Seleziona tutti" compaiono solo quando ci sono davvero file isolabili (i file del core si riportano all'originale con "Ripristina originale").

= 1.2.1 =
* Versione di prova per verificare l'aggiornamento automatico dal pannello WordPress.

= 1.2.0 =
* Aggiornamenti dal pannello WordPress: il plugin controlla le release del repository GitHub e mostra "Aggiornamento disponibile" nella pagina Plugin, con installazione a un clic. Nessuno zip da scaricare a mano.
* In Impostazioni: versione installata, ultima disponibile e pulsante "Controlla aggiornamenti ora". Link "Controlla aggiornamenti" anche nella riga del plugin.

= 1.1.4 =
* Selezione multipla, "Seleziona tutti" e pulizia in blocco anche nella pagina Database.

= 1.1.3 =
* Nella pagina Scansione: casella di selezione su ogni file, "Seleziona tutti" e pulsante per mettere in quarantena più file in una volta sola.
* I file estranei dentro wp-admin/wp-includes ora possono essere messi in quarantena (restano protetti wp-config.php e il plugin stesso).

= 1.1.2 =
* Ogni elemento trovato dalle scansioni (file e database) mostra ora un livello di criticità (Alta / Media / Bassa) con una spiegazione di cosa significa e come proteggersi.
* Risultati ordinati per criticità e criticità inclusa anche nelle email di notifica.

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
