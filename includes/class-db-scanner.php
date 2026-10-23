<?php
/**
 * Scanner del database.
 *
 * Cerca codice iniettato (script, iframe, offuscamenti) in:
 *  - wp_options  (option_value) — bersaglio frequente
 *  - wp_posts    (post_content, post_excerpt)
 *  - wp_comments (comment_content)
 *
 * La pulizia è conservativa: prima di modificare salva l'originale in
 * una "quarantena del database", poi rimuove solo i blocchi <script> e
 * <iframe>. Tutto è ripristinabile.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_DB_Scanner {

	private $logger;

	const QUARANTINE_OPTION = 'sg_db_quarantine';

	// Pattern che confermano un contenuto sospetto.
	private $patterns = array(
		'/<script[\s>]/i'                     => 'Tag <script> nel contenuto',
		'/<iframe[\s>]/i'                     => 'Tag <iframe> nel contenuto',
		'/eval\s*\(/i'                        => 'Chiamata eval()',
		'/base64_decode\s*\(/i'               => 'base64_decode()',
		'/document\.write\s*\(/i'             => 'document.write()',
		'/String\.fromCharCode\s*\(/i'        => 'String.fromCharCode() (offuscamento)',
		'/(\\\\x[0-9a-f]{2}){8,}/i'           => 'Sequenza esadecimale lunga',
		'/window\.location\s*=/i'             => 'Redirect JavaScript',
		'/atob\s*\(/i'                        => 'atob() (decodifica base64 JS)',
	);

	// Marcatori per la pre-selezione via SQL LIKE (più veloce).
	private $like_markers = array( '<script', '<iframe', 'eval(', 'base64_decode', 'document.write', 'fromCharCode', 'atob(' );

	public function __construct( $logger ) {
		$this->logger = $logger;
	}

	/* ===================================================================
	 *  SCANSIONE
	 * =================================================================== */

	public function full_db_scan() {
		$findings = array_merge(
			$this->scan_options(),
			$this->scan_posts(),
			$this->scan_comments()
		);

		// Aggiunge criticità e consigli di protezione a ogni elemento.
		foreach ( $findings as &$f ) {
			$meta          = $this->classify( $f['reason'] );
			$f['severity'] = $meta['severity'];
			$f['detail']   = $meta['detail'];
			// Contenuti creati da plugin (snippet di codice CSS/JS, ecc.):
			// lo <script> è quasi sempre legittimo e "Pulisci" rimuoverebbe
			// il codice del plugin. Abbassiamo e avvisiamo.
			if ( ! empty( $f['label'] ) && 0 === strpos( $f['label'], 'Contenuto plugin' ) ) {
				$f['severity'] = 'bassa';
				$f['detail']   = 'Questo non è un articolo del blog ma un contenuto gestito da un plugin (tipico dei plugin di codice/snippet CSS e JavaScript). Lo script qui è quasi sempre legittimo. NON usare "Pulisci" se non sei sicuro: rimuoverebbe il codice del plugin. Verificalo dal pannello del plugin che lo gestisce.';
			}
		}
		unset( $f );

		$rank = array( 'alta' => 0, 'media' => 1, 'bassa' => 2 );
		usort( $findings, function ( $a, $b ) use ( $rank ) {
			$ra = isset( $rank[ $a['severity'] ] ) ? $rank[ $a['severity'] ] : 3;
			$rb = isset( $rank[ $b['severity'] ] ) ? $rank[ $b['severity'] ] : 3;
			return $ra <=> $rb;
		} );

		update_option( 'sg_last_db_scan', array(
			'findings'   => $findings,
			'scanned_at' => current_time( 'mysql' ),
		), false );

		$this->logger->log(
			'scan_db',
			sprintf( 'Scansione database: %d elementi sospetti.', count( $findings ) ),
			count( $findings ) > 0 ? 'warning' : 'info'
		);

		return $findings;
	}

	private function like_where( $column ) {
		global $wpdb;
		$clauses = array();
		foreach ( $this->like_markers as $marker ) {
			$clauses[] = $wpdb->prepare( "$column LIKE %s", '%' . $wpdb->esc_like( $marker ) . '%' );
		}
		return '(' . implode( ' OR ', $clauses ) . ')';
	}

	public function scan_options() {
		global $wpdb;
		$found = array();
		$where = $this->like_where( 'option_value' );
		// Escludiamo:
		// - le nostre stesse opzioni (sg_*);
		// - i transient di WordPress (cache che si rigenera da sola e che
		//   contiene spesso HTML legittimo scaricato da wordpress.org:
		//   _transient_*, _site_transient_* e i relativi timeout).
		$rows = $wpdb->get_results(
			"SELECT option_id, option_name, option_value FROM {$wpdb->options}
			 WHERE $where
			   AND option_name NOT LIKE 'sg\_%'
			   AND option_name NOT LIKE '\_transient\_%'
			   AND option_name NOT LIKE '\_site\_transient\_%'
			 LIMIT 500"
		);
		foreach ( (array) $rows as $row ) {
			$reason = $this->match( $row->option_value );
			if ( $reason ) {
				$found[] = array(
					'source'  => 'option',
					'id'      => $row->option_name,
					'label'   => 'Opzione: ' . $row->option_name,
					'reason'  => $reason,
					'snippet' => $this->snippet( $row->option_value ),
				);
			}
		}
		return $found;
	}

	public function scan_posts() {
		global $wpdb;
		$found = array();
		$where = $this->like_where( 'post_content' );
		$rows  = $wpdb->get_results(
			"SELECT ID, post_title, post_type, post_content FROM {$wpdb->posts}
			 WHERE $where AND post_status NOT IN ('trash','auto-draft') LIMIT 500"
		);
		// Tipi standard a cui il pubblico accede: per gli altri (contenuti
		// creati da plugin, es. snippet di codice CSS/JS) lo indichiamo nel
		// nome, perché lì lo <script> è di norma legittimo.
		$standard = array( 'post', 'page' );
		foreach ( (array) $rows as $row ) {
			$reason = $this->match( $row->post_content );
			if ( $reason ) {
				$type = $row->post_type;
				if ( in_array( $type, $standard, true ) ) {
					$label = ( 'page' === $type ? 'Pagina #' : 'Articolo #' ) . $row->ID . ': ' . $row->post_title;
				} else {
					// Contenuto di un plugin: segnaliamo il tipo, è il caso
					// tipico dei plugin di codice (snippet CSS/JS).
					$label = 'Contenuto plugin #' . $row->ID . ' [tipo: ' . $type . ']: ' . $row->post_title;
				}
				$found[] = array(
					'source'  => 'post',
					'id'      => $row->ID,
					'label'   => $label,
					'reason'  => $reason,
					'snippet' => $this->snippet( $row->post_content ),
				);
			}
		}
		return $found;
	}

	public function scan_comments() {
		global $wpdb;
		$found = array();
		$where = $this->like_where( 'comment_content' );
		$rows  = $wpdb->get_results(
			"SELECT comment_ID, comment_content FROM {$wpdb->comments}
			 WHERE $where LIMIT 500"
		);
		foreach ( (array) $rows as $row ) {
			$reason = $this->match( $row->comment_content );
			if ( $reason ) {
				$found[] = array(
					'source'  => 'comment',
					'id'      => $row->comment_ID,
					'label'   => 'Commento #' . $row->comment_ID,
					'reason'  => $reason,
					'snippet' => $this->snippet( $row->comment_content ),
				);
			}
		}
		return $found;
	}

	private function match( $content ) {
		foreach ( $this->patterns as $pattern => $reason ) {
			if ( preg_match( $pattern, (string) $content ) ) {
				return $reason;
			}
		}
		return false;
	}

	/**
	 * Criticità e consigli per un elemento sospetto del database.
	 */
	public function classify( $reason ) {
		$alta = array(
			'Chiamata eval()',
			'base64_decode()',
			'document.write()',
			'String.fromCharCode() (offuscamento)',
			'Redirect JavaScript',
			'atob() (decodifica base64 JS)',
		);
		if ( in_array( $reason, $alta, true ) ) {
			return array(
				'severity' => 'alta',
				'detail'   => 'Nel database c\'è codice JavaScript offuscato o un redirect: segno tipico di un sito violato (spam, truffe, reindirizzamenti verso siti esterni). Usa "Pulisci" (rimuove solo il codice pericoloso e salva l\'originale), poi cambia le password e aggiorna temi e plugin.',
			);
		}
		// <script> / <iframe> / sequenze esadecimali: spesso iniezioni,
		// ma a volte contenuti legittimi (embed, widget).
		return array(
			'severity' => 'media',
			'detail'   => 'Contenuto con script o iframe: potrebbe essere un\'iniezione, oppure un embed legittimo che hai inserito tu (es. un video o un widget). Se riconosci il contenuto, ignora; altrimenti usa "Pulisci" (è reversibile).',
		);
	}

	private function snippet( $content ) {
		$content = (string) $content;
		foreach ( $this->patterns as $pattern => $reason ) {
			if ( preg_match( $pattern, $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$pos   = max( 0, $m[0][1] - 40 );
				$piece = substr( $content, $pos, 160 );
				return '…' . trim( $piece ) . '…';
			}
		}
		return substr( $content, 0, 160 );
	}

	/* ===================================================================
	 *  PULIZIA (con backup ripristinabile)
	 * =================================================================== */

	/**
	 * Rimuove i blocchi <script> e <iframe> da un contenuto,
	 * dopo aver salvato l'originale in quarantena.
	 */
	public function clean( $source, $id ) {
		switch ( $source ) {
			case 'option':
				return $this->clean_option( $id );
			case 'post':
				return $this->clean_post( (int) $id );
			case 'comment':
				return $this->clean_comment( (int) $id );
		}
		return new WP_Error( 'sg_bad_source', 'Origine non valida.' );
	}

	private function strip_malicious( $content ) {
		$content = preg_replace( '#<script\b[^>]*>.*?</script>#is', '', $content );
		$content = preg_replace( '#<iframe\b[^>]*>.*?</iframe>#is', '', $content );
		$content = preg_replace( '#<iframe\b[^>]*/?>#is', '', $content );
		return $content;
	}

	private function backup( $source, $id, $original ) {
		$q = get_option( self::QUARANTINE_OPTION, array() );
		$key = $source . ':' . $id . ':' . time();
		$q[ $key ] = array(
			'source'   => $source,
			'id'       => $id,
			'original' => $original,
			'date'     => current_time( 'mysql' ),
		);
		update_option( self::QUARANTINE_OPTION, $q, false );
		return $key;
	}

	private function clean_option( $name ) {
		$value = get_option( $name );
		if ( ! is_string( $value ) ) {
			return new WP_Error( 'sg_not_text', 'Questa opzione non è testo semplice: puliscila a mano con cautela.' );
		}
		$this->backup( 'option', $name, $value );
		$clean = $this->strip_malicious( $value );
		update_option( $name, $clean );
		$this->logger->log( 'db_clean', 'Pulita opzione: ' . $name, 'info' );
		return true;
	}

	private function clean_post( $id ) {
		$post = get_post( $id );
		if ( ! $post ) {
			return new WP_Error( 'sg_no_post', 'Articolo non trovato.' );
		}
		$this->backup( 'post', $id, $post->post_content );
		$clean = $this->strip_malicious( $post->post_content );
		wp_update_post( array( 'ID' => $id, 'post_content' => $clean ) );
		$this->logger->log( 'db_clean', 'Pulito articolo #' . $id, 'info' );
		return true;
	}

	private function clean_comment( $id ) {
		$comment = get_comment( $id );
		if ( ! $comment ) {
			return new WP_Error( 'sg_no_comment', 'Commento non trovato.' );
		}
		$this->backup( 'comment', $id, $comment->comment_content );
		$clean = $this->strip_malicious( $comment->comment_content );
		wp_update_comment( array( 'comment_ID' => $id, 'comment_content' => $clean ) );
		$this->logger->log( 'db_clean', 'Pulito commento #' . $id, 'info' );
		return true;
	}

	/* ===================================================================
	 *  RIPRISTINO DALLA QUARANTENA DEL DATABASE
	 * =================================================================== */

	public function get_quarantine() {
		return get_option( self::QUARANTINE_OPTION, array() );
	}

	public function restore( $key ) {
		$q = $this->get_quarantine();
		if ( ! isset( $q[ $key ] ) ) {
			return new WP_Error( 'sg_no_backup', 'Backup non trovato.' );
		}
		$item = $q[ $key ];
		switch ( $item['source'] ) {
			case 'option':
				update_option( $item['id'], $item['original'] );
				break;
			case 'post':
				wp_update_post( array( 'ID' => (int) $item['id'], 'post_content' => $item['original'] ) );
				break;
			case 'comment':
				wp_update_comment( array( 'comment_ID' => (int) $item['id'], 'comment_content' => $item['original'] ) );
				break;
		}
		unset( $q[ $key ] );
		update_option( self::QUARANTINE_OPTION, $q, false );
		$this->logger->log( 'db_restore', 'Ripristinato dal DB: ' . $item['source'] . ' ' . $item['id'], 'info' );
		return true;
	}

	public function get_last_scan() {
		return get_option( 'sg_last_db_scan', array() );
	}
}
