<?php
/**
 * Protezione contro il brute force sul login.
 * Conta i tentativi falliti per IP e blocca temporaneamente
 * chi supera la soglia.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Brute_Force {

	private $logger;
	private $max_attempts;
	private $lockout_seconds;

	public function __construct( $logger, $settings ) {
		$this->logger          = $logger;
		$this->max_attempts    = absint( $settings['max_login_attempts'] );
		$this->lockout_seconds = absint( $settings['lockout_minutes'] ) * 60;
	}

	public function boot() {
		// Blocca prima ancora di controllare le credenziali.
		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 1 );
		// Conta i fallimenti.
		add_action( 'wp_login_failed', array( $this, 'on_failed_login' ) );
		// Azzera il contatore dopo un login riuscito.
		add_action( 'wp_login', array( $this, 'on_successful_login' ) );
		// Messaggio di errore neutro, non rivela se l'utente esiste.
		add_filter( 'login_errors', array( $this, 'generic_error' ) );
	}

	private function transient_key( $ip = null ) {
		$ip = $ip ? $ip : SG_Logger::get_ip();
		return 'sg_bf_' . md5( $ip );
	}

	public function check_lockout( $user ) {
		$key      = $this->transient_key();
		$attempts = (int) get_transient( $key );

		if ( $attempts >= $this->max_attempts ) {
			return new WP_Error(
				'sg_locked_out',
				sprintf(
					/* translators: %d = minuti di blocco */
					__( 'Troppi tentativi falliti. Riprova tra %d minuti.', 'security-guardian' ),
					ceil( $this->lockout_seconds / 60 )
				)
			);
		}
		return $user;
	}

	public function on_failed_login( $username ) {
		$key      = $this->transient_key();
		$attempts = (int) get_transient( $key );
		$attempts++;
		set_transient( $key, $attempts, $this->lockout_seconds );

		if ( $attempts >= $this->max_attempts ) {
			$this->logger->log(
				'login_lockout',
				sprintf( 'IP bloccato dopo %d tentativi. Ultimo username provato: %s', $attempts, sanitize_user( $username ) ),
				'warning'
			);
		} else {
			$this->logger->log(
				'login_failed',
				sprintf( 'Tentativo fallito (%d/%d). Username: %s', $attempts, $this->max_attempts, sanitize_user( $username ) ),
				'info'
			);
		}
	}

	public function on_successful_login( $username ) {
		delete_transient( $this->transient_key() );
	}

	public function generic_error( $error ) {
		// Se c'è un blocco mostriamo il nostro messaggio, altrimenti
		// uniformiamo il messaggio per non rivelare dettagli.
		$attempts = (int) get_transient( $this->transient_key() );
		if ( $attempts >= $this->max_attempts ) {
			return $error;
		}
		return __( 'Credenziali non valide.', 'security-guardian' );
	}
}
