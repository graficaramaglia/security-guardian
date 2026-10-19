<?php
/**
 * Indurimento di WordPress: disattiva funzioni rischiose,
 * blocca l'enumerazione utenti e aggiunge header di sicurezza.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Hardening {

	private $settings;

	public function __construct( $settings ) {
		$this->settings = $settings;
	}

	public function boot() {

		// Disattiva XML-RPC, bersaglio frequente di brute force e DDoS.
		if ( ! empty( $this->settings['hardening_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		}

		// Nasconde la versione di WordPress.
		if ( ! empty( $this->settings['hardening_hide_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		// Disattiva l'editor di plugin e temi nel pannello admin.
		if ( ! empty( $this->settings['hardening_file_editor'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// Blocca l'enumerazione degli utenti.
		if ( ! empty( $this->settings['hardening_enum'] ) ) {
			add_action( 'init', array( $this, 'block_user_enumeration' ) );
			add_filter( 'rest_endpoints', array( $this, 'restrict_users_endpoint' ) );
		}

		// Header di sicurezza.
		if ( ! empty( $this->settings['hardening_headers'] ) ) {
			add_filter( 'wp_headers', array( $this, 'add_security_headers' ) );
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
		}
	}

	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Blocca gli accessi tipo /?author=1 che rivelano gli username.
	 */
	public function block_user_enumeration() {
		if ( is_admin() ) {
			return;
		}
		if ( isset( $_GET['author'] ) && preg_match( '/^\d+$/', (string) $_GET['author'] ) ) {
			$this->deny( 'Tentativo di enumerazione utenti via ?author.' );
		}
	}

	/**
	 * Rende inaccessibile l'elenco utenti via REST agli utenti non loggati.
	 */
	public function restrict_users_endpoint( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		if ( isset( $endpoints['/wp/v2/users'] ) ) {
			unset( $endpoints['/wp/v2/users'] );
		}
		if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}
		return $endpoints;
	}

	public function add_security_headers( $headers ) {
		$headers['X-Content-Type-Options'] = 'nosniff';
		$headers['X-Frame-Options']        = 'SAMEORIGIN';
		$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
		return $headers;
	}

	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
		// HSTS solo se il sito è in HTTPS.
		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
		}
	}

	private function deny( $reason ) {
		$guardian = SG_Guardian::instance();
		if ( isset( $guardian->logger ) ) {
			$guardian->logger->log( 'enumeration_block', $reason, 'warning' );
		}
		status_header( 403 );
		wp_die( esc_html__( 'Accesso negato.', 'security-guardian' ), 403 );
	}
}
