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

	// Firme euristiche: pattern spesso presenti nel codice malevolo.
	private $malware_signatures = array(
		'/eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/i' => 'Codice offuscato eseguito con eval()',
		'/\b(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\(/i'      => 'Payload compresso e codificato',
		'/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i'                                 => 'preg_replace con modificatore /e (esecuzione codice)',
		'/\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(/'                        => 'Chiamata a funzione da input utente (possibile backdoor)',
		'/assert\s*\(\s*\$_(POST|GET|REQUEST)/i'                                  => 'assert() su input utente',
		'/\bcreate_function\s*\(/i'                                               => 'create_function (tecnica da webshell)',
		'/base64_decode\s*\([\'"][A-Za-z0-9+\/=]{200,}/'                          => 'Lunga stringa base64 (payload nascosto)',
		'/\\\\x[0-9a-f]{2}(\\\\x[0-9a-f]{2}){10,}/i'                              => 'Sequenza esadecimale lunga (offuscamento)',
		'/FilesMan|c99shell|r57shell|WSO\s|b374k/i'                               => 'Firma di webshell nota',
		'/move_uploaded_file\s*\([^)]*\.(php|phtml)/i'                            => 'Upload di file PHP',
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

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $fileinfo ) {
			if ( ! $fileinfo->isFile() ) {
				continue;
			}
			$path = $fileinfo->getPathname();
			$ext  = strtolower( $fileinfo->getExtension() );

			// Un .php dentro uploads è quasi sempre un problema.
			$uploads = wp_upload_dir();
			if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'phar' ), true )
				&& 0 === strpos( $path, $uploads['basedir'] ) ) {
				$threats[] = array(
					'file'   => $path,
					'reason' => 'File PHP nella cartella uploads (non dovrebbe esistere)',
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
}
