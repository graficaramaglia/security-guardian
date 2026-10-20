<?php
/**
 * Scanner di sicurezza.
 *
 * 1. Core: confronta i file del core di WordPress con i checksum
 *    ufficiali pubblicati dalle API di WordPress.org.
 * 2. Euristica: cerca nei file PHP (temi, plugin, uploads) i pattern
 *    tipici di malware e backdoor.
 *
 * La scansione è a blocchi per non andare in timeout sui siti grandi.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Scanner {

	private $logger;
	private $quarantine;

	// Firme euristiche basate su COMBINAZIONI tipiche del malware.
	// Volutamente NON usiamo indicatori singoli e deboli (base64_decode da
	// solo, lunghe sequenze esadecimali, create_function da solo): compaiono
	// di continuo nel codice legittimo — librerie di crittografia, polyfill,
	// file minificati — e generano solo falsi positivi.
	private $malware_signatures = array(
		// eval() di un payload decodificato al volo.
		'/\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|convert_uudecode)\s*\(/i' => 'eval() di un payload codificato',
		// eval()/assert() direttamente su input utente.
		'/\b(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\b/i' => 'Esecuzione di codice da input utente',
		// assert() di un payload decodificato.
		'/\bassert\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/i' => 'assert() di un payload codificato',
		// Catena di decodifica/decompressione annidata.
		'/\b(gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*base64_decode\s*\(/i' => 'Payload compresso e codificato',
		// Funzione il cui nome arriva da input utente: $_POST[...]().
		'/\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/' => 'Chiamata a funzione da input utente (possibile backdoor)',
		// preg_replace con modificatore /e (esecuzione di codice).
		'/preg_replace\s*\(\s*[\'"][^\'"]{0,300}\/e[imsxuADSUX]*[\'"]/i' => 'preg_replace con modificatore /e',
		// create_function solo se costruita da payload o input utente.
		'/\bcreate_function\s*\([^)]{0,200}(base64_decode|gzinflate|\$_(POST|GET|REQUEST|COOKIE))/i' => 'create_function con payload o input utente',
		// Nomi di webshell note.
		'/\b(c99shell|r57shell|b374k|wsoshell|filesman\b.{0,40}\bshell)\b/i' => 'Firma di webshell nota',
		// Caricamento di un file PHP via upload.
		'/\bmove_uploaded_file\s*\([^)]*\.(php|phtml|php[0-9])\b/i' => 'Upload di un file PHP',
		// NB: la firma "scrittura di codice PHP in un file" è stata rimossa:
		// troppi plugin legittimi (cache, migrazioni, generatori di config)
		// scrivono file PHP, quindi generava solo falsi positivi. I dropper
		// reali vengono comunque colti dalle firme eval/base64/input utente.
	);

	public function __construct( $logger, $quarantine ) {
		$this->logger     = $logger;
		$this->quarantine = $quarantine;
	}

	/* ===================================================================
	 *  SCANSIONE DEL CORE
	 * =================================================================== */

	/**
	 * Scarica i checksum ufficiali per la versione e la lingua in uso.
	 *
	 * @return array|WP_Error Mappa [percorso relativo => md5].
	 */
	public function get_official_checksums() {
		global $wp_version;
		$locale = get_locale();

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$checksums = get_core_checksums( $wp_version, $locale );

		if ( false === $checksums && 'en_US' !== $locale ) {
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $checksums ) ) {
			return new WP_Error( 'sg_no_checksums', 'Impossibile scaricare i checksum ufficiali di WordPress.' );
		}
		return $checksums;
	}

	/**
	 * Confronta i file del core con i checksum ufficiali.
	 *
	 * @return array|WP_Error modified[], missing[], unknown[]
	 */
	public function scan_core() {
		$checksums = $this->get_official_checksums();
		if ( is_wp_error( $checksums ) ) {
			return $checksums;
		}

		$result = array(
			'modified' => array(),
			'missing'  => array(),
			'unknown'  => array(),
		);

		foreach ( $checksums as $file => $hash ) {
			// wp-content è gestito dall'utente: non fa parte del core verificabile.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			// File del core "innocui" che differiscono di continuo senza che
			// ci sia un attacco: pagine statiche (readme/licenza), file di
			// esempio mai eseguiti e file legati alla lingua. Su installazioni
			// non inglesi questi divergono sempre dall'originale ufficiale, e
			// non contengono codice attivo del sito.
			if ( $this->is_ignorable_core_file( $file ) ) {
				continue;
			}
			$path = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				$result['missing'][] = $file;
				continue;
			}
			if ( md5_file( $path ) !== $hash ) {
				$result['modified'][] = $file;
			}
		}

		// Cerca file estranei nelle cartelle del core.
		$result['unknown'] = $this->find_unknown_core_files( $checksums );

		$this->logger->log(
			'scan_core',
			sprintf(
				'Scansione core: %d modificati, %d mancanti, %d estranei.',
				count( $result['modified'] ),
				count( $result['missing'] ),
				count( $result['unknown'] )
			),
			count( $result['modified'] ) + count( $result['unknown'] ) > 0 ? 'warning' : 'info'
		);

		return $result;
	}

	/**
	 * File del core da ignorare nel confronto checksum: non contengono
	 * codice eseguito dal sito e differiscono spesso in modo innocuo
	 * (installazioni localizzate, hosting che rimarca il readme, ecc.).
	 */
	private function is_ignorable_core_file( $rel ) {
		$rel     = strtolower( str_replace( '\\', '/', $rel ) );
		$ignore  = array(
			'readme.html',
			'license.txt',
			'wp-config-sample.php',
			'wp-includes/version.php',
		);
		if ( in_array( $rel, $ignore, true ) ) {
			return true;
		}
		// Licenze tradotte: license.it_IT.txt, readme-*.html, ecc.
		if ( preg_match( '#^(license|readme)[.\-][a-z0-9_\-]+\.(txt|html)$#', $rel ) ) {
			return true;
		}
		return false;
	}

	private function find_unknown_core_files( $checksums ) {
		$unknown = array();
		$dirs    = array( 'wp-admin', 'wp-includes' );

		foreach ( $dirs as $dir ) {
			$base = ABSPATH . $dir;
			if ( ! is_dir( $base ) ) {
				continue;
			}
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $iterator as $fileinfo ) {
				if ( ! $fileinfo->isFile() ) {
					continue;
				}
				$rel = str_replace( ABSPATH, '', $fileinfo->getPathname() );
				$rel = str_replace( '\\', '/', $rel );
				if ( ! isset( $checksums[ $rel ] ) && preg_match( '/\.(php|phtml|php5|php7|phar)$/i', $rel ) ) {
					$unknown[] = $rel;
				}
			}
		}
		return $unknown;
	}

	/**
	 * Ripristina un file del core scaricando l'originale ufficiale.
	 *
	 * @param string $relative_file Percorso relativo, es. wp-includes/pluggable.php
	 * @return true|WP_Error
	 */
	public function restore_core_file( $relative_file ) {
		global $wp_version;

		// Sicurezza: solo file del core, mai dentro wp-content.
		$relative_file = ltrim( str_replace( '\\', '/', $relative_file ), '/' );
		if ( 0 === strpos( $relative_file, 'wp-content/' ) || false !== strpos( $relative_file, '..' ) ) {
			return new WP_Error( 'sg_invalid_path', 'Percorso non valido per il ripristino.' );
		}

		$url = sprintf( 'https://core.svn.wordpress.org/tags/%s/%s', $wp_version, $relative_file );

		$response = wp_remote_get( $url, array( 'timeout' => 30 ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'sg_download_failed', 'File originale non trovato sul server ufficiale.' );
		}
		$content = wp_remote_retrieve_body( $response );

		$target = ABSPATH . $relative_file;

		// Backup del file attuale in quarantena prima di sovrascrivere.
		if ( file_exists( $target ) ) {
			$this->quarantine->backup( $target );
		}

		wp_mkdir_p( dirname( $target ) );
		$written = file_put_contents( $target, $content );

		if ( false === $written ) {
			return new WP_Error( 'sg_write_failed', 'Impossibile scrivere il file ripristinato (permessi?).' );
		}

		$this->logger->log( 'restore_core', 'Ripristinato file del core: ' . $relative_file, 'info' );
		return true;
	}

	/* ===================================================================
	 *  SCANSIONE EURISTICA (temi, plugin, uploads)
	 * =================================================================== */

	/**
	 * Scansiona una cartella alla ricerca di codice sospetto.
	 *
	 * @return array Elenco di minacce [file, reason].
	 */
	public function scan_directory( $dir ) {
		$threats = array();
		if ( ! is_dir( $dir ) ) {
			return $threats;
		}

		$self_dir = wp_normalize_path( SG_PATH );
		$uploads  = wp_upload_dir();

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $fileinfo ) {
			if ( ! $fileinfo->isFile() ) {
				continue;
			}
			$path = $fileinfo->getPathname();
			$ext  = strtolower( $fileinfo->getExtension() );

			// Non analizziamo la cartella del plugin stesso: le sue firme
			// contengono le parole chiave del malware e si auto-segnalerebbe.
			if ( 0 === strpos( wp_normalize_path( $path ), $self_dir ) ) {
				continue;
			}

			// Un .php dentro uploads merita attenzione, ma ignoriamo i file
			// "guardiano" innocui (index.php vuoti, blocchi ABSPATH) che molti
			// plugin legittimi inseriscono lì.
			if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'phar' ), true )
				&& 0 === strpos( $path, $uploads['basedir'] ) ) {
				$content = $fileinfo->getSize() < 1024 * 1024 ? file_get_contents( $path ) : '';
				if ( '' !== $content && $this->is_benign_php( $content ) ) {
					continue;
				}
				$threats[] = array(
					'file'   => $path,
					'reason' => 'File PHP nella cartella uploads (da verificare)',
					'type'   => 'uploads_php',
				);
				continue;
			}

			if ( ! in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'phar', 'js' ), true ) ) {
				continue;
			}
			// Evita file troppo grandi (librerie minificate, ecc.).
			if ( $fileinfo->getSize() > 3 * 1024 * 1024 ) {
				continue;
			}

			$content = file_get_contents( $path );
			if ( false === $content ) {
				continue;
			}

			foreach ( $this->malware_signatures as $pattern => $reason ) {
				if ( preg_match( $pattern, $content ) ) {
					$threats[] = array(
						'file'   => $path,
						'reason' => $reason,
						'type'   => 'heuristic',
					);
					break; // una segnalazione per file è sufficiente
				}
			}
		}

		return $threats;
	}

	/**
	 * Vero se il file PHP è un "guardiano" innocuo: vuoto, solo commenti,
	 * oppure il classico blocco di protezione (exit / die / controllo ABSPATH).
	 */
	private function is_benign_php( $content ) {
		// Rimuove i commenti.
		$c = preg_replace( '!/\*.*?\*/!s', '', $content );
		$c = preg_replace( '@//.*$@m', '', $c );
		$c = preg_replace( '/#.*$/m', '', $c );
		// Rimuove i tag PHP.
		$c = str_replace( array( '<?php', '<?=', '<?', '?>' ), '', $c );
		$c = trim( $c );

		if ( '' === $c ) {
			return true;
		}
		// Solo exit; / die;
		if ( preg_match( '/^(exit|die)\s*(\([^)]*\))?\s*;?$/i', $c ) ) {
			return true;
		}
		// if ( ! defined('ABSPATH') ) exit;  (eventualmente con graffe)
		if ( preg_match( '/^if\s*\(\s*!?\s*defined\s*\(\s*[\'"]ABSPATH[\'"]\s*\)\s*\)\s*\{?\s*(exit|die|return)\s*(\([^)]*\))?\s*;?\s*\}?$/i', $c ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Scansione completa: core + contenuti.
	 */
	public function full_scan() {
		$core    = $this->scan_core();
		$threats = array();

		// Minacce dal confronto core.
		if ( ! is_wp_error( $core ) ) {
			foreach ( $core['modified'] as $f ) {
				$threats[] = array( 'file' => $f, 'reason' => 'File del core modificato', 'type' => 'core_modified' );
			}
			foreach ( $core['unknown'] as $f ) {
				$threats[] = array( 'file' => $f, 'reason' => 'File estraneo nelle cartelle del core', 'type' => 'core_unknown' );
			}
		}

		// Minacce euristiche nei contenuti.
		$threats = array_merge( $threats, $this->scan_directory( WP_CONTENT_DIR . '/themes' ) );
		$threats = array_merge( $threats, $this->scan_directory( WP_CONTENT_DIR . '/plugins' ) );
		$threats = array_merge( $threats, $this->scan_directory( wp_upload_dir()['basedir'] ) );

		// Aggiunge a ogni elemento la criticità e i consigli di protezione.
		foreach ( $threats as &$t ) {
			$meta         = $this->classify( $t['type'], $t['reason'] );
			$t['severity'] = $meta['severity'];
			$t['detail']   = $meta['detail'];
		}
		unset( $t );

		// Ordina per criticità (alta prima).
		usort( $threats, array( $this, 'sort_by_severity' ) );

		$results = array(
			'core'      => is_wp_error( $core ) ? array() : $core,
			'core_error'=> is_wp_error( $core ) ? $core->get_error_message() : '',
			'threats'   => $threats,
			'scanned_at'=> current_time( 'mysql' ),
		);

		update_option( 'sg_last_scan', $results, false );

		$this->logger->log(
			'scan_full',
			sprintf( 'Scansione completa terminata: %d elementi da esaminare.', count( $threats ) ),
			count( $threats ) > 0 ? 'warning' : 'info'
		);

		return $results;
	}

	public function get_last_scan() {
		return get_option( 'sg_last_scan', array() );
	}

	/**
	 * Assegna criticità (alta/media/bassa) e consigli di protezione
	 * a un elemento trovato dalla scansione dei file.
	 */
	public function classify( $type, $reason ) {
		// Elementi del core.
		if ( 'core_modified' === $type ) {
			return array(
				'severity' => 'alta',
				'detail'   => 'Un file del core di WordPress è diverso dall\'originale ufficiale. Se non l\'hai modificato tu, è un segnale forte di manomissione. Usa "Ripristina originale", poi cambia le password (admin, FTP, database) e rigenera le chiavi di sicurezza in wp-config.php.',
			);
		}
		if ( 'core_unknown' === $type ) {
			return array(
				'severity' => 'alta',
				'detail'   => 'File estraneo dentro wp-admin o wp-includes, dove normalmente non si aggiunge nulla: è la posizione tipica delle backdoor. Mettilo in quarantena ed esamina il sito.',
			);
		}
		if ( 'uploads_php' === $type ) {
			return array(
				'severity' => 'media',
				'detail'   => 'Un file PHP nella cartella uploads di solito non dovrebbe esistere. A volte è legittimo: controlla dal percorso a quale plugin appartiene. Se non lo riconosci, mettilo in quarantena.',
			);
		}

		// Elementi euristici: criticità in base al motivo.
		$alta = array(
			'eval() di un payload codificato',
			'Esecuzione di codice da input utente',
			'assert() di un payload codificato',
			'Payload compresso e codificato',
			'Chiamata a funzione da input utente (possibile backdoor)',
			'create_function con payload o input utente',
			'Firma di webshell nota',
		);
		if ( in_array( $reason, $alta, true ) ) {
			return array(
				'severity' => 'alta',
				'detail'   => 'Questo file contiene uno schema tipico delle backdoor (codice nascosto che esegue comandi inviati dall\'esterno). Se non sai spiegarne la presenza, mettilo subito in quarantena, poi cambia tutte le password e controlla gli utenti amministratori.',
			);
		}

		// Restanti euristici: criticità media.
		return array(
			'severity' => 'media',
			'detail'   => 'Il file usa una tecnica che il malware sfrutta spesso, ma che in rari casi può essere legittima. Verifica a quale plugin o tema appartiene; nel dubbio, mettilo in quarantena (è reversibile).',
		);
	}

	public function sort_by_severity( $a, $b ) {
		$rank = array( 'alta' => 0, 'media' => 1, 'bassa' => 2 );
		$ra   = isset( $rank[ $a['severity'] ] ) ? $rank[ $a['severity'] ] : 3;
		$rb   = isset( $rank[ $b['severity'] ] ) ? $rank[ $b['severity'] ] : 3;
		return $ra <=> $rb;
	}
}
