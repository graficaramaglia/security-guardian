<?php
/**
 * Quarantena e ripristino.
 *
 * Invece di cancellare subito un file sospetto, lo sposta in una
 * cartella protetta e lo rende non eseguibile. Da lì si può
 * ripristinare (se falso positivo) o eliminare definitivamente.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Quarantine {

	const INDEX_OPTION = 'sg_quarantine_index';

	private $logger;

	public function __construct( $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Crea la cartella di quarantena e la blinda.
	 */
	public static function setup_directory() {
		if ( ! is_dir( SG_QUARANTINE_DIR ) ) {
			wp_mkdir_p( SG_QUARANTINE_DIR );
		}
		// Nega ogni accesso web alla cartella.
		$htaccess = SG_QUARANTINE_DIR . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Deny from all\n<IfModule mod_authz_core.c>\n Require all denied\n</IfModule>\n" );
		}
		// Impedisce il listing della cartella.
		$index = SG_QUARANTINE_DIR . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php // Silence is golden.\n" );
		}
	}

	/**
	 * Mette un file in quarantena.
	 *
	 * @param string $file Percorso assoluto del file infetto.
	 * @return true|WP_Error
	 */
	public function quarantine_file( $file ) {
		$file = wp_normalize_path( $file );

		if ( ! file_exists( $file ) ) {
			return new WP_Error( 'sg_not_found', 'File non trovato.' );
		}
		// Non permettiamo mai di spostare file del core o del plugin stesso.
		if ( $this->is_protected( $file ) ) {
			return new WP_Error( 'sg_protected', 'Questo file è protetto e non può essere messo in quarantena da qui.' );
		}

		self::setup_directory();

		$id          = uniqid( 'q_', true );
		$dest        = SG_QUARANTINE_DIR . '/' . $id . '.quar';

		if ( ! @rename( $file, $dest ) ) {
			// Se rename fallisce (es. filesystem diverso), copia e cancella.
			if ( ! @copy( $file, $dest ) || ! @unlink( $file ) ) {
				return new WP_Error( 'sg_move_failed', 'Impossibile spostare il file in quarantena (permessi?).' );
			}
		}
		@chmod( $dest, 0600 );

		$index          = $this->get_index();
		$index[ $id ]   = array(
			'original' => $file,
			'date'     => current_time( 'mysql' ),
		);
		update_option( self::INDEX_OPTION, $index, false );

		$this->logger->log( 'quarantine', 'File messo in quarantena: ' . $file, 'warning' );
		return true;
	}

	/**
	 * Ripristina un file dalla quarantena alla posizione originale.
	 */
	public function restore_file( $id ) {
		$index = $this->get_index();
		if ( ! isset( $index[ $id ] ) ) {
			return new WP_Error( 'sg_unknown', 'Elemento di quarantena non trovato.' );
		}
		$src  = SG_QUARANTINE_DIR . '/' . $id . '.quar';
		$dest = $index[ $id ]['original'];

		if ( ! file_exists( $src ) ) {
			return new WP_Error( 'sg_missing', 'File di quarantena mancante.' );
		}
		wp_mkdir_p( dirname( $dest ) );
		if ( ! @rename( $src, $dest ) ) {
			return new WP_Error( 'sg_restore_failed', 'Impossibile ripristinare il file.' );
		}
		unset( $index[ $id ] );
		update_option( self::INDEX_OPTION, $index, false );

		$this->logger->log( 'quarantine_restore', 'File ripristinato dalla quarantena: ' . $dest, 'info' );
		return true;
	}

	/**
	 * Elimina definitivamente un file in quarantena.
	 */
	public function delete_file( $id ) {
		$index = $this->get_index();
		if ( ! isset( $index[ $id ] ) ) {
			return new WP_Error( 'sg_unknown', 'Elemento di quarantena non trovato.' );
		}
		$src = SG_QUARANTINE_DIR . '/' . $id . '.quar';
		if ( file_exists( $src ) ) {
			@unlink( $src );
		}
		$original = $index[ $id ]['original'];
		unset( $index[ $id ] );
		update_option( self::INDEX_OPTION, $index, false );

		$this->logger->log( 'quarantine_delete', 'File eliminato definitivamente: ' . $original, 'info' );
		return true;
	}

	/**
	 * Salva una copia di backup di un file prima di sovrascriverlo
	 * (usato dal ripristino del core).
	 */
	public function backup( $file ) {
		self::setup_directory();
		$id   = uniqid( 'bak_', true );
		$dest = SG_QUARANTINE_DIR . '/' . $id . '.quar';
		@copy( $file, $dest );
		$index        = $this->get_index();
		$index[ $id ] = array(
			'original' => wp_normalize_path( $file ),
			'date'     => current_time( 'mysql' ),
			'note'     => 'Backup pre-ripristino',
		);
		update_option( self::INDEX_OPTION, $index, false );
	}

	public function get_index() {
		return get_option( self::INDEX_OPTION, array() );
	}

	/**
	 * Impedisce la quarantena di file sensibili.
	 *
	 * NB: non blocchiamo in blocco wp-admin/wp-includes, perché lì possono
	 * annidarsi i file estranei (core_unknown) che vogliamo poter isolare.
	 * I file legittimi del core non vengono mai proposti per la quarantena
	 * (per quelli c'è il ripristino dall'originale ufficiale).
	 */
	private function is_protected( $file ) {
		$file = wp_normalize_path( $file );
		// Il plugin stesso.
		if ( 0 === strpos( $file, wp_normalize_path( SG_PATH ) ) ) {
			return true;
		}
		// Il file di configurazione non si tocca mai.
		if ( basename( $file ) === 'wp-config.php' ) {
			return true;
		}
		// Il file deve stare dentro l'installazione WordPress.
		if ( 0 !== strpos( $file, wp_normalize_path( ABSPATH ) ) ) {
			return true;
		}
		return false;
	}
}
