<?php
/**
 * Mini firewall applicativo (WAF).
 * Ispeziona le richieste in ingresso e blocca i pattern tipici
 * di SQL injection, XSS, path traversal e scansione di file sensibili.
 *
 * Le regole possono essere estese da remoto scaricando un file JSON
 * firmato (gestito dal modulo aggiornamenti, previsto nella v2).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Firewall {

	private $logger;

	public function __construct( $logger ) {
		$this->logger = $logger;
	}

	public function boot() {
		// Agiamo presto, ma dopo che WP ha caricato le funzioni di base.
		$this->inspect_request();
	}

	/**
	 * Regole di base. Ognuna ha un'etichetta e un pattern regex.
	 * Vengono applicate ai valori di GET, POST, cookie e query string.
	 */
	private function get_rules() {
		$rules = array(
			'sql_injection' => array(
				'/union[\s\/\*]+select/i',
				'/\bselect\b.+\bfrom\b.+\bwhere\b/i',
				'/(\%27)|(\')(\s)*(or|and)(\s)*\d+(\s)*=(\s)*\d+/i',
				'/benchmark\s*\(/i',
				'/sleep\s*\(\s*\d+\s*\)/i',
				'/load_file\s*\(/i',
				'/into\s+outfile/i',
			),
			'xss' => array(
				'/<script[^>]*>/i',
				'/javascript\s*:/i',
				'/onerror\s*=/i',
				'/onload\s*=/i',
				'/document\.cookie/i',
				'/<iframe[^>]*>/i',
			),
			'path_traversal' => array(
				'/\.\.[\/\\\\]/',
				'/(\%2e){2}(\%2f|\%5c)/i',
				'/\/etc\/passwd/i',
				'/php:\/\/(input|filter)/i',
			),
			'file_probe' => array(
				'/wp-config\.php(\.bak|\.old|~|\.save|\.txt)/i',
				'/\.(env|git|svn|htpasswd)\b/i',
				'/phpinfo\(\)/i',
			),
			'rce' => array(
				'/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i',
				'/base64_decode\s*\(/i',
			),
		);

		// Punto di estensione per regole caricate da remoto.
		return apply_filters( 'sg_firewall_rules', $rules );
	}

	private function inspect_request() {
		// Non ispezioniamo le richieste degli utenti amministratori loggati,
		// per ridurre i falsi positivi nel pannello.
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$targets = $this->collect_input();
		$rules   = $this->get_rules();

		foreach ( $targets as $value ) {
			if ( ! is_string( $value ) || '' === $value ) {
				continue;
			}
			foreach ( $rules as $category => $patterns ) {
				foreach ( $patterns as $pattern ) {
					if ( preg_match( $pattern, $value ) ) {
						$this->block( $category, $value );
					}
				}
			}
		}
	}

	/**
	 * Raccoglie e appiattisce tutti i valori in ingresso.
	 */
	private function collect_input() {
		$values = array();

		$sources = array( $_GET, $_POST, $_COOKIE );
		if ( isset( $_SERVER['QUERY_STRING'] ) ) {
			$values[] = rawurldecode( $_SERVER['QUERY_STRING'] );
		}
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$values[] = rawurldecode( $_SERVER['REQUEST_URI'] );
		}

		foreach ( $sources as $source ) {
			array_walk_recursive(
				$source,
				function ( $item ) use ( &$values ) {
					$values[] = $item;
				}
			);
		}
		return $values;
	}

	private function block( $category, $value ) {
		$snippet = substr( (string) $value, 0, 200 );
		$this->logger->log(
			'firewall_block',
			sprintf( 'Bloccata richiesta [%s]: %s', $category, $snippet ),
			'critical'
		);
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html__( 'La tua richiesta è stata bloccata dal firewall di sicurezza.', 'security-guardian' ),
			esc_html__( 'Richiesta bloccata', 'security-guardian' ),
			array( 'response' => 403 )
		);
	}
}
