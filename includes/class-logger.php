<?php
/**
 * Registro attività. Salva gli eventi di sicurezza in una tabella
 * dedicata del database.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Logger {

	public static function table_name() {
		global $wpdb;
		return $wpdb->prefix . 'sg_log';
	}

	public static function create_table() {
		global $wpdb;
		$table           = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE $table (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			ip VARCHAR(45) DEFAULT '',
			message TEXT NOT NULL,
			PRIMARY KEY (id),
			KEY event_type (event_type),
			KEY created_at (created_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Registra un evento.
	 *
	 * @param string $type     Tipo di evento (login_failed, firewall_block, scan, ...).
	 * @param string $message  Descrizione.
	 * @param string $severity info | warning | critical.
	 */
	public function log( $type, $message, $severity = 'info' ) {
		global $wpdb;
		$wpdb->insert(
			self::table_name(),
			array(
				'created_at' => current_time( 'mysql' ),
				'event_type' => $type,
				'severity'   => $severity,
				'ip'         => self::get_ip(),
				'message'    => $message,
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);
	}

	public function get_recent( $limit = 100 ) {
		global $wpdb;
		$table = self::table_name();
		$limit = absint( $limit );
		return $wpdb->get_results( "SELECT * FROM $table ORDER BY id DESC LIMIT $limit" );
	}

	public function clear() {
		global $wpdb;
		$table = self::table_name();
		$wpdb->query( "TRUNCATE TABLE $table" );
	}

	/**
	 * Ricava l'IP del visitatore in modo prudente.
	 * Di default usa REMOTE_ADDR, l'unico non falsificabile dal client.
	 */
	public static function get_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}
}
