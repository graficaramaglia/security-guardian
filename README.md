<h1 align="center">🛡️ Security Guardian</h1>

<p align="center">
  <strong>La sicurezza di WordPress, tutta in un unico plugin.</strong><br>
  Protezione in tempo reale, scansione intelligente, pulizia e ripristino, autenticazione a due fattori e aggiornamenti automatici.
</p>

<p align="center">
  <img alt="Versione" src="https://img.shields.io/badge/versione-2.1.0-2271b1">
  <img alt="WordPress" src="https://img.shields.io/badge/WordPress-5.6%2B-21759b">
  <img alt="PHP" src="https://img.shields.io/badge/PHP-7.4%2B-777bb4">
  <img alt="Licenza" src="https://img.shields.io/badge/licenza-GPL--2.0-green">
  <img alt="WooCommerce" src="https://img.shields.io/badge/WooCommerce-compatibile-96588a">
</p>

---

## Perché Security Guardian

Ogni sito WordPress, dal blog personale al negozio online, è sotto attacco ogni giorno: bot che provano migliaia di password, scanner che cercano file di configurazione esposti, tentativi di iniezione di codice. La maggior parte dei proprietari di siti se ne accorge solo **dopo** essere stata violata.

**Security Guardian** nasce per cambiare questo: mette insieme in un solo strumento le difese essenziali di un sito WordPress, con un'interfaccia chiara in italiano che ti dice **cosa sta succedendo** e **cosa fare**, senza bisogno di essere un esperto di sicurezza.

Niente da configurare per partire: si installa, si attiva, e protegge. Da lì puoi affinare ogni dettaglio.

---

## Cosa fa, in breve

| Area | Funzione |
|------|----------|
| 🧱 **Protezione** | Firewall applicativo, anti brute force, indurimento di WordPress |
| 🔎 **Scansione** | Core, temi, plugin, cartella uploads e database |
| 🧯 **Rimedio** | Quarantena reversibile, ripristino dei file originali, pulizia del database |
| 🔐 **Accesso** | Autenticazione a due fattori (2FA) selezionabile per ruolo |
| 🔄 **Manutenzione** | Aggiornamenti automatici dal pannello, scansioni pianificate, notifiche email |

---

## Le funzioni in dettaglio

### 🧱 Protezione in tempo reale

- **Firewall applicativo (WAF)** — Ispeziona ogni richiesta in arrivo e blocca i pattern tipici di **SQL injection**, **Cross-Site Scripting (XSS)**, **path traversal** e la scansione di file sensibili (`.env`, `wp-config.bak`, `.git`…). Riconosce anche le varianti "offuscate" usate per aggirare i filtri ingenui.
- **Esclusioni per i pagamenti** — I webhook dei gateway (**PayPal, Stripe, Klarna** e gli altri via WooCommerce) sono esclusi automaticamente: le conferme di pagamento non vengono mai bloccate. Puoi aggiungere percorsi personalizzati, e l'esclusione agisce solo sul path dell'URL — non può essere sfruttata per aggirare il firewall.
- **Protezione brute force** — Limita i tentativi di accesso falliti per IP e blocca temporaneamente chi supera la soglia. Soglia e durata del blocco configurabili. Messaggi di errore neutri, che non rivelano se un utente esiste.
- **Indurimento di WordPress** — Con un clic: disattiva XML-RPC, blocca l'enumerazione degli utenti (`?author=` e REST), nasconde la versione di WordPress, disabilita l'editor di file nel pannello e aggiunge gli header di sicurezza (`X-Frame-Options`, `Content-Type-Options`, `Referrer-Policy`, HSTS…).

### 🔎 Scansione intelligente

- **Controllo del core** — Confronta ogni file del core di WordPress con i **checksum ufficiali** di wordpress.org e individua file **modificati, mancanti o estranei**. Ignora in automatico i file che differiscono in modo innocuo (readme, licenze, file localizzati).
- **Scanner euristico** — Analizza temi, plugin e la cartella uploads cercando malware e backdoor tramite **firme basate su combinazioni** (es. codice codificato eseguito al volo, comandi presi da input utente, webshell note). Poche firme ma precise, pensate per ridurre al minimo i falsi positivi.
- **Scansione del database** — Cerca codice iniettato (script, iframe, redirect, offuscamenti) in articoli, opzioni e commenti. Salta automaticamente la cache interna di WordPress e le revisioni, e distingue i contenuti creati dai plugin (es. snippet CSS/JS) dagli articoli veri.

### 🚦 Criticità e consigli

Ogni elemento trovato è classificato con un livello di **criticità — Alta, Media, Bassa** — e accompagnato da una spiegazione di **cosa significa** e **come proteggersi**. I risultati sono ordinati dal più grave, così sai subito dove guardare.

### 🧯 Quarantena e ripristino

- **Quarantena** — Invece di cancellare subito un file sospetto, lo isola in una cartella protetta e non eseguibile. Se era un falso positivo lo ripristini con un clic; altrimenti lo elimini definitivamente. Selezione multipla e azione in blocco.
- **Ripristino degli originali** — Per i file del core modificati, scarica e ripristina la versione ufficiale corretta con un clic.
- **Pulizia del database** — Rimuove solo il codice pericoloso dai contenuti infetti, salvando sempre l'originale in una quarantena dedicata, così ogni intervento è reversibile.

### 🔐 Autenticazione a due fattori (2FA)

- Basata sullo standard **TOTP** (RFC 6238): compatibile con Google Authenticator, Authy, Microsoft Authenticator, 1Password e qualsiasi app di autenticazione.
- **Codici di backup** monouso per non restare mai chiusi fuori.
- **Selezionabile per ruolo** — Scegli a chi si applica: solo gli amministratori, anche gli editori, non i clienti o i sottoscrittori. Perfetta per i negozi WooCommerce.

### 🔄 Manutenzione automatica

- **Aggiornamenti dal pannello** — Il plugin si aggiorna da solo tramite le release di GitHub, come qualsiasi plugin: quando esce una nuova versione, la vedi nella pagina Plugin e la installi con un clic.
- **Scansioni pianificate** — Ogni ora, due volte al giorno o ogni giorno, a scelta.
- **Notifiche email** — Ricevi un riepilogo quando una scansione trova qualcosa da verificare.
- **Registro attività** — Ogni evento (accessi falliti, blocchi del firewall, scansioni, azioni 2FA) è tracciato e consultabile.

---

## Installazione

1. Scarica l'ultima release: **[Releases](../../releases/latest)** → scarica `security-guardian-x.y.z.zip`.
2. In WordPress: **Plugin → Aggiungi nuovo → Carica plugin** → seleziona lo zip → **Installa** → **Attiva**.
3. Apri il menu **Security Guardian** e avvia la prima scansione.

> 💡 Da qui in poi, gli aggiornamenti arrivano automaticamente nel pannello: non dovrai più scaricare nulla a mano.

**Requisiti:** WordPress 5.6+ · PHP 7.4+

---

## Per i negozi online (WooCommerce)

Security Guardian è pensato anche per gli e-commerce:

- I **webhook di pagamento** di PayPal, Stripe e Klarna sono esclusi dal firewall per impostazione predefinita.
- La **2FA** di default si applica solo agli amministratori: i clienti non vengono disturbati al login.
- Consiglio: installalo **prima del lancio**, fai un **acquisto di prova** e controlla il registro, così parti con la certezza che tutto fili liscio.

---

## Buone pratiche

Un plugin di sicurezza è un livello di difesa, non l'unico. Per un sito davvero protetto:

- Mantieni aggiornati **core, temi e plugin**.
- Usa **password robuste** e attiva la **2FA** sugli account amministratore.
- Tieni **backup regolari** fuori dal server.
- Dopo aver ripulito un sito compromesso, cambia tutte le password (admin, FTP, database) e rigenera le chiavi di sicurezza in `wp-config.php`.

---

## Licenza

Distribuito sotto licenza **GPL-2.0-or-later**. Vedi il file [LICENSE](LICENSE).

<p align="center"><sub>Fatto con cura per tenere al sicuro i siti WordPress.</sub></p>
