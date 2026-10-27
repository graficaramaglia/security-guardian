<?php
/**
 * Orchestratore principale: collega tutti i moduli e gestisce
 * attivazione, opzioni e pianificazione delle scansioni.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Guardian {

	private static $instance = null;

	public $logger;
	public $brute_force;
	public $hardening;
	public $firewall;
	public $scanner;
	public $db_scanner;
	public $quarantine;
	public $two_factor;
	public $updater;
	public $admin;

	const OPTION_KEY = 'sg_settings';

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$settings = $this->get_settings();

		$this->logger     = new SG_Logger();
		$this->quarantine = new SG_Quarantine( $this->logger );
		$this->scanner    = new SG_Scanner( $this->logger, $this->quarantine );
		$this->db_scanner = new SG_DB_Scanner( $this->logger );

		// Autenticazione a due fattori (con i ruoli a cui si applica).
		$roles            = isset( $settings['twofactor_roles'] ) && is_array( $settings['twofactor_roles'] )
			? $settings['twofactor_roles']
			: array( 'administrator' );
		$this->two_factor = new SG_TwoFactor( $this->logger, $roles );
		if ( ! empty( $settings['twofactor_enabled'] ) ) {
			$this->two_factor->boot();
		}

		// Aggiornamenti automatici da GitHub.
		$this->updater = new SG_Updater( 'graficaramaglia', 'security-guardian', SG_BASENAME, SG_VERSION );
		$this->updater->boot();

		// Il firewall deve agire il prima possibile, già a plugins_loaded.
		if ( ! empty( $settings['firewall_enabled'] ) ) {
			$exclusions = isset( $settings['firewall_exclusions'] ) && is_array( $settings['firewall_exclusions'] )
				? $settings['firewall_exclusions']
				: array();
			$this->firewall = new SG_Firewall( $this->logger, $exclusions );
			$this->firewall->boot();
		}

		if ( ! empty( $settings['brute_force_enabled'] ) ) {
			$this->brute_force = new SG_Brute_Force( $this->logger, $settings );
			$this->brute_force->boot();
		}

		$this->hardening = new SG_Hardening( $settings );
		$this->hardening->boot();

		// Pannello di amministrazione.
		if ( is_admin() ) {
			$this->admin = new SG_Admin( $this );
			$this->admin->boot();
		}

		// Scansione pianificata via WP-Cron.
		add_action( 'sg_scheduled_scan', array( $this, 'run_scheduled_scan' ) );
	}

	/**
	 * Impostazioni con valori di default.
	 */
	public function get_settings() {
		$defaults = array(
			'firewall_enabled'      => 1,
			'firewall_exclusions'   => array(),
			'brute_force_enabled'   => 1,
			'max_login_attempts'    => 5,
			'lockout_minutes'       => 20,
			'hardening_xmlrpc'      => 1,
			'hardening_enum'        => 1,
			'hardening_headers'     => 1,
			'hardening_file_editor' => 1,
			'hardening_hide_version'=> 1,
			'scan_schedule'         => 'daily',
			'notify_email'          => get_option( 'admin_email' ),
			'notify_enabled'        => 1,
			'twofactor_enabled'     => 1,
			'twofactor_roles'       => array( 'administrator' ),
		);
		$saved = get_option( self::OPTION_KEY, array() );
		return wp_parse_args( $saved, $defaults );
	}

	public function update_settings( $new ) {
		update_option( self::OPTION_KEY, $new );
		$this->reschedule_scan( $new['scan_schedule'] );
	}

	public function run_scheduled_scan() {
		$results = $this->scanner->full_scan();
		$db      = $this->db_scanner->full_db_scan();
		$settings = $this->get_settings();

		$total = count( $results['threats'] ) + count( $db );
		if ( ! empty( $settings['notify_enabled'] ) && $total > 0 ) {
			$this->send_threat_email( $results, $db, $settings['notify_email'] );
		}
	}

	private function send_threat_email( $results, $db, $email ) {
		$count   = count( $results['threats'] ) + count( $db );
		$subject = sprintf( '[Security Guardian] %d possibili minacce su %s', $count, get_bloginfo( 'name' ) );
		$body    = "La scansione pianificata ha trovato elementi sospetti.\n\n";

		if ( ! empty( $results['threats'] ) ) {
			$body .= "FILE:\n";
			foreach ( $results['threats'] as $t ) {
				$body .= sprintf( "- [criticità %s] %s — %s\n", strtoupper( $t['severity'] ?? 'media' ), $t['reason'], $t['file'] );
			}
			$body .= "\n";
		}
		if ( ! empty( $db ) ) {
			$body .= "DATABASE:\n";
			foreach ( $db as $d ) {
				$body .= sprintf( "- [criticità %s] %s — %s\n", strtoupper( $d['severity'] ?? 'media' ), $d['label'], $d['reason'] );
			}
			$body .= "\n";
		}
		$body .= "Apri il pannello Security Guardian per esaminarli: " . admin_url( 'admin.php?page=security-guardian-scanner' );
		wp_mail( $email, $subject, $body );
	}

	private function reschedule_scan( $schedule ) {
		$timestamp = wp_next_scheduled( 'sg_scheduled_scan' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'sg_scheduled_scan' );
		}
		if ( 'none' !== $schedule ) {
			wp_schedule_event( time() + 3600, $schedule, 'sg_scheduled_scan' );
		}
	}

	/**
	 * Attivazione del plugin.
	 */
	public static function on_activate() {
		// Crea la tabella dei log.
		SG_Logger::create_table();

		// Crea e protegge la cartella di quarantena.
		SG_Quarantine::setup_directory();

		// Pianifica la prima scansione.
		if ( ! wp_next_scheduled( 'sg_scheduled_scan' ) ) {
			wp_schedule_event( time() + 3600, 'daily', 'sg_scheduled_scan' );
		}
	}

	public static function on_deactivate() {
		$timestamp = wp_next_scheduled( 'sg_scheduled_scan' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'sg_scheduled_scan' );
		}
	}
}
