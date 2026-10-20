<?php
/**
 * Plugin Name:       Security Guardian
 * Plugin URI:        https://github.com/graficaramaglia/security-guardian
 * Description:       Protezione, scansione e ripristino per WordPress: anti brute force, indurimento, mini firewall, scanner del core e del database, quarantena, ripristino degli originali e 2FA.
 * Version:           1.2.3
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Giovanni
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       security-guardian
 * Update URI:        https://github.com/graficaramaglia/security-guardian
 */

// Blocca l'accesso diretto al file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SG_VERSION', '1.2.3' );
define( 'SG_FILE', __FILE__ );
define( 'SG_PATH', plugin_dir_path( __FILE__ ) );
define( 'SG_URL', plugin_dir_url( __FILE__ ) );
define( 'SG_BASENAME', plugin_basename( __FILE__ ) );

// Cartella di quarantena, fuori dalla vista del web.
define( 'SG_QUARANTINE_DIR', WP_CONTENT_DIR . '/sg-quarantine' );

// Carica le classi del plugin.
require_once SG_PATH . 'includes/class-logger.php';
require_once SG_PATH . 'includes/class-brute-force.php';
require_once SG_PATH . 'includes/class-hardening.php';
require_once SG_PATH . 'includes/class-firewall.php';
require_once SG_PATH . 'includes/class-scanner.php';
require_once SG_PATH . 'includes/class-db-scanner.php';
require_once SG_PATH . 'includes/class-quarantine.php';
require_once SG_PATH . 'includes/class-twofactor.php';
require_once SG_PATH . 'includes/class-updater.php';
require_once SG_PATH . 'includes/class-admin.php';
require_once SG_PATH . 'includes/class-guardian.php';

// Avvia il plugin.
function sg_run() {
	return SG_Guardian::instance();
}
add_action( 'plugins_loaded', 'sg_run', 1 );

// Attivazione: crea tabelle e cartelle, imposta i valori di default.
register_activation_hook( __FILE__, array( 'SG_Guardian', 'on_activate' ) );
register_deactivation_hook( __FILE__, array( 'SG_Guardian', 'on_deactivate' ) );
