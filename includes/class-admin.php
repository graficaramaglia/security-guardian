<?php
/**
 * Pannello di amministrazione: dashboard, scanner, quarantena,
 * log e impostazioni. Gestisce anche le azioni (scansione,
 * ripristino, quarantena, eliminazione) con nonce e controllo permessi.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Admin {

	private $guardian;
	private $cap = 'manage_options';

	public function __construct( $guardian ) {
		$this->guardian = $guardian;
	}

	public function boot() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_sg_action', array( $this, 'handle_action' ) );
		add_action( 'wp_ajax_sg_run_scan', array( $this, 'ajax_run_scan' ) );
		add_action( 'wp_ajax_sg_run_db_scan', array( $this, 'ajax_run_db_scan' ) );
	}

	public function add_menu() {
		add_menu_page(
			'Security Guardian',
			'Security Guardian',
			$this->cap,
			'security-guardian',
			array( $this, 'page_dashboard' ),
			'dashicons-shield-alt',
			80
		);
		add_submenu_page( 'security-guardian', 'Dashboard', 'Dashboard', $this->cap, 'security-guardian', array( $this, 'page_dashboard' ) );
		add_submenu_page( 'security-guardian', 'Scansione', 'Scansione', $this->cap, 'security-guardian-scanner', array( $this, 'page_scanner' ) );
		add_submenu_page( 'security-guardian', 'Database', 'Database', $this->cap, 'security-guardian-database', array( $this, 'page_database' ) );
		add_submenu_page( 'security-guardian', 'Quarantena', 'Quarantena', $this->cap, 'security-guardian-quarantine', array( $this, 'page_quarantine' ) );
		add_submenu_page( 'security-guardian', '2FA', 'Autenticazione 2FA', $this->cap, 'security-guardian-2fa', array( $this, 'page_2fa' ) );
		add_submenu_page( 'security-guardian', 'Registro', 'Registro', $this->cap, 'security-guardian-log', array( $this, 'page_log' ) );
		add_submenu_page( 'security-guardian', 'Impostazioni', 'Impostazioni', $this->cap, 'security-guardian-settings', array( $this, 'page_settings' ) );
	}

	public function assets( $hook ) {
		if ( false === strpos( $hook, 'security-guardian' ) ) {
			return;
		}
		wp_enqueue_style( 'sg-admin', SG_URL . 'assets/admin.css', array(), SG_VERSION );
		wp_enqueue_script( 'sg-admin', SG_URL . 'assets/admin.js', array( 'jquery' ), SG_VERSION, true );
		wp_localize_script( 'sg-admin', 'sgData', array(
			'ajaxurl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'sg_scan_nonce' ),
			'scanning'=> __( 'Scansione in corso…', 'security-guardian' ),
		) );
	}

	/* ----------------------------------------------------------------
	 *  AZIONI
	 * ---------------------------------------------------------------- */

	public function handle_action() {
		if ( ! current_user_can( $this->cap ) ) {
			wp_die( 'Permesso negato.' );
		}
		check_admin_referer( 'sg_action' );

		// La maggior parte delle azioni arriva da form POST; "check_updates"
		// arriva da un link GET, quindi leggiamo da $_REQUEST.
		$action = isset( $_REQUEST['sg_do'] ) ? sanitize_key( $_REQUEST['sg_do'] ) : '';
		$notice = '';

		switch ( $action ) {

			case 'save_settings':
				$this->save_settings();
				$notice = 'settings_saved';
				break;

			case 'restore_core':
				$file = isset( $_POST['file'] ) ? wp_unslash( $_POST['file'] ) : '';
				$res  = $this->guardian->scanner->restore_core_file( $file );
				$notice = is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'restored';
				break;

			case 'quarantine':
				$file = isset( $_POST['file'] ) ? wp_unslash( $_POST['file'] ) : '';
				$res  = $this->guardian->quarantine->quarantine_file( $file );
				$notice = is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'quarantined';
				break;

			case 'q_restore':
				$id  = isset( $_POST['qid'] ) ? sanitize_text_field( $_POST['qid'] ) : '';
				$res = $this->guardian->quarantine->restore_file( $id );
				$notice = is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'q_restored';
				break;

			case 'q_delete':
				$id  = isset( $_POST['qid'] ) ? sanitize_text_field( $_POST['qid'] ) : '';
				$res = $this->guardian->quarantine->delete_file( $id );
				$notice = is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'q_deleted';
				break;

			case 'bulk_quarantine':
				$files = isset( $_POST['files'] ) ? (array) wp_unslash( $_POST['files'] ) : array();
				$done  = 0;
				$fail  = 0;
				foreach ( $files as $file ) {
					$res = $this->guardian->quarantine->quarantine_file( $file );
					if ( is_wp_error( $res ) ) {
						$fail++;
					} else {
						$done++;
					}
				}
				$notice = 'bulk:' . $done . ':' . $fail;
				break;

			case 'db_clean':
				$source = isset( $_POST['source'] ) ? sanitize_key( $_POST['source'] ) : '';
				$id     = isset( $_POST['id'] ) ? wp_unslash( $_POST['id'] ) : '';
				$res    = $this->guardian->db_scanner->clean( $source, $id );
				$notice = is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'db_cleaned';
				break;

			case 'bulk_clean':
				$items = isset( $_POST['items'] ) ? (array) wp_unslash( $_POST['items'] ) : array();
				$done  = 0;
				$fail  = 0;
				foreach ( $items as $item ) {
					$parts  = explode( '|', $item, 2 );
					$source = isset( $parts[0] ) ? sanitize_key( $parts[0] ) : '';
					$id     = isset( $parts[1] ) ? $parts[1] : '';
					if ( '' === $source || '' === $id ) {
						$fail++;
						continue;
					}
					$res = $this->guardian->db_scanner->clean( $source, $id );
					if ( is_wp_error( $res ) ) {
						$fail++;
					} else {
						$done++;
					}
				}
				$notice = 'bulkclean:' . $done . ':' . $fail;
				break;

			case 'db_restore':
				$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
				$res = $this->guardian->db_scanner->restore( $key );
				$notice = is_wp_error( $res ) ? 'error:' . $res->get_error_message() : 'db_restored';
				break;

			case '2fa_start':
				$this->guardian->two_factor->start_setup( get_current_user_id() );
				$notice = '2fa_started';
				break;

			case '2fa_confirm':
				$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
				$res  = $this->guardian->two_factor->confirm_setup( get_current_user_id(), $code );
				if ( is_wp_error( $res ) ) {
					$notice = 'error:' . $res->get_error_message();
				} else {
					// Mostra i codici di backup una sola volta.
					set_transient( 'sg_2fa_codes_' . get_current_user_id(), $res, 300 );
					$notice = '2fa_enabled';
				}
				break;

			case '2fa_disable':
				$this->guardian->two_factor->disable( get_current_user_id() );
				$notice = '2fa_disabled';
				break;

			case '2fa_cancel':
				$this->guardian->two_factor->cancel_setup( get_current_user_id() );
				$notice = '2fa_cancelled';
				break;

			case '2fa_regen':
				$res = $this->guardian->two_factor->generate_backup_codes( get_current_user_id() );
				set_transient( 'sg_2fa_codes_' . get_current_user_id(), $res, 300 );
				$notice = '2fa_regen';
				break;

			case 'check_updates':
				$this->guardian->updater->force_check();
				$notice = 'update_checked';
				break;

			case 'clear_log':
				$this->guardian->logger->clear();
				$notice = 'log_cleared';
				break;
		}

		$back = isset( $_REQUEST['_back'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_back'] ) ) : 'security-guardian';
		if ( 'plugins' === $back ) {
			$redirect = admin_url( 'plugins.php?sg_notice=' . rawurlencode( $notice ) );
		} else {
			$redirect = admin_url( 'admin.php?page=' . $back . '&sg_notice=' . rawurlencode( $notice ) );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	private function save_settings() {
		$s = $this->guardian->get_settings();

		$checkboxes = array(
			'firewall_enabled', 'brute_force_enabled', 'hardening_xmlrpc',
			'hardening_enum', 'hardening_headers', 'hardening_file_editor',
			'hardening_hide_version', 'notify_enabled', 'twofactor_enabled',
		);
		foreach ( $checkboxes as $cb ) {
			$s[ $cb ] = isset( $_POST[ $cb ] ) ? 1 : 0;
		}
		$s['max_login_attempts'] = max( 1, absint( $_POST['max_login_attempts'] ?? 5 ) );
		$s['lockout_minutes']    = max( 1, absint( $_POST['lockout_minutes'] ?? 20 ) );
		$s['notify_email']       = sanitize_email( $_POST['notify_email'] ?? get_option( 'admin_email' ) );
		$schedule                = sanitize_key( $_POST['scan_schedule'] ?? 'daily' );
		$s['scan_schedule']      = in_array( $schedule, array( 'hourly', 'daily', 'twicedaily', 'none' ), true ) ? $schedule : 'daily';

		// Ruoli a cui si applica la 2FA: solo ruoli realmente esistenti.
		$valid_roles = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array( 'administrator' );
		$posted      = isset( $_POST['twofactor_roles'] ) ? (array) wp_unslash( $_POST['twofactor_roles'] ) : array();
		$posted      = array_values( array_intersect( array_map( 'sanitize_key', $posted ), $valid_roles ) );
		$s['twofactor_roles'] = ! empty( $posted ) ? $posted : array( 'administrator' );

		$this->guardian->update_settings( $s );
	}

	public function ajax_run_scan() {
		check_ajax_referer( 'sg_scan_nonce', 'nonce' );
		if ( ! current_user_can( $this->cap ) ) {
			wp_send_json_error( 'Permesso negato.' );
		}
		@set_time_limit( 0 );
		$results = $this->guardian->scanner->full_scan();
		wp_send_json_success( array(
			'threats' => count( $results['threats'] ),
			'time'    => $results['scanned_at'],
		) );
	}

	public function ajax_run_db_scan() {
		check_ajax_referer( 'sg_scan_nonce', 'nonce' );
		if ( ! current_user_can( $this->cap ) ) {
			wp_send_json_error( 'Permesso negato.' );
		}
		@set_time_limit( 0 );
		$findings = $this->guardian->db_scanner->full_db_scan();
		wp_send_json_success( array( 'findings' => count( $findings ) ) );
	}

	/* ----------------------------------------------------------------
	 *  PAGINE
	 * ---------------------------------------------------------------- */

	private function notice() {
		if ( empty( $_GET['sg_notice'] ) ) {
			return;
		}
		$n   = sanitize_text_field( wp_unslash( $_GET['sg_notice'] ) );
		$map = array(
			'settings_saved' => array( 'success', 'Impostazioni salvate.' ),
			'restored'       => array( 'success', 'File del core ripristinato all\'originale.' ),
			'quarantined'    => array( 'success', 'File messo in quarantena.' ),
			'q_restored'     => array( 'success', 'File ripristinato dalla quarantena.' ),
			'q_deleted'      => array( 'success', 'File eliminato definitivamente.' ),
			'log_cleared'    => array( 'success', 'Registro svuotato.' ),
			'db_cleaned'     => array( 'success', 'Elemento del database pulito (originale salvato in quarantena DB).' ),
			'db_restored'    => array( 'success', 'Elemento del database ripristinato all\'originale.' ),
			'2fa_started'    => array( 'info', 'Scansiona la chiave con l\'app e conferma con un codice.' ),
			'2fa_enabled'    => array( 'success', '2FA attivata. Salva subito i codici di backup qui sotto.' ),
			'2fa_disabled'   => array( 'success', '2FA disattivata per il tuo account.' ),
			'2fa_cancelled'  => array( 'info', 'Configurazione 2FA annullata. Puoi ricominciare quando vuoi.' ),
			'2fa_regen'      => array( 'success', 'Nuovi codici di backup generati. Salvali ora.' ),
			'update_checked' => array( 'success', 'Controllo aggiornamenti eseguito. Se è disponibile una nuova versione, la vedrai nella pagina Plugin.' ),
		);
		if ( 0 === strpos( $n, 'error:' ) ) {
			printf( '<div class="notice notice-error is-dismissible"><p>%s</p></div>', esc_html( substr( $n, 6 ) ) );
		} elseif ( 0 === strpos( $n, 'bulk:' ) ) {
			$parts = explode( ':', $n );
			$done  = isset( $parts[1] ) ? intval( $parts[1] ) : 0;
			$fail  = isset( $parts[2] ) ? intval( $parts[2] ) : 0;
			$type  = $fail > 0 ? 'warning' : 'success';
			$msg   = sprintf( '%d file messi in quarantena.', $done );
			if ( $fail > 0 ) {
				$msg .= sprintf( ' %d non è stato possibile spostarli (protetti o non accessibili).', $fail );
			}
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $type ), esc_html( $msg ) );
		} elseif ( 0 === strpos( $n, 'bulkclean:' ) ) {
			$parts = explode( ':', $n );
			$done  = isset( $parts[1] ) ? intval( $parts[1] ) : 0;
			$fail  = isset( $parts[2] ) ? intval( $parts[2] ) : 0;
			$type  = $fail > 0 ? 'warning' : 'success';
			$msg   = sprintf( '%d elementi del database puliti (originali salvati in quarantena DB).', $done );
			if ( $fail > 0 ) {
				$msg .= sprintf( ' %d non puliti.', $fail );
			}
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $type ), esc_html( $msg ) );
		} elseif ( isset( $map[ $n ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $n ][0] ), esc_html( $map[ $n ][1] ) );
		}
	}

	public function page_dashboard() {
		$last = $this->guardian->scanner->get_last_scan();
		$logs = $this->guardian->logger->get_recent( 8 );
		$threats = isset( $last['threats'] ) ? count( $last['threats'] ) : null;
		?>
		<div class="wrap sg-wrap">
			<h1><span class="dashicons dashicons-shield-alt"></span> Security Guardian</h1>
			<?php $this->notice(); ?>

			<div class="sg-cards">
				<div class="sg-card <?php echo ( $threats > 0 ) ? 'sg-danger' : 'sg-ok'; ?>">
					<h2><?php echo ( null === $threats ) ? '—' : intval( $threats ); ?></h2>
					<p>Elementi da esaminare</p>
				</div>
				<div class="sg-card sg-info">
					<h2><?php echo esc_html( $last['scanned_at'] ?? 'Mai' ); ?></h2>
					<p>Ultima scansione</p>
				</div>
				<div class="sg-card sg-info">
					<h2><?php echo esc_html( count( $this->guardian->quarantine->get_index() ) ); ?></h2>
					<p>File in quarantena</p>
				</div>
			</div>

			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-guardian-scanner' ) ); ?>" class="button button-primary button-hero">Avvia una scansione</a>
			</p>

			<h2>Stato della protezione</h2>
			<?php $s = $this->guardian->get_settings(); ?>
			<table class="widefat sg-status">
				<tbody>
					<?php
					$this->status_row( 'Firewall applicativo', $s['firewall_enabled'] );
					$this->status_row( 'Protezione brute force', $s['brute_force_enabled'] );
					$this->status_row( 'XML-RPC disattivato', $s['hardening_xmlrpc'] );
					$this->status_row( 'Blocco enumerazione utenti', $s['hardening_enum'] );
					$this->status_row( 'Header di sicurezza', $s['hardening_headers'] );
					$this->status_row( 'Editor file disattivato', $s['hardening_file_editor'] );
					$this->status_row( 'Autenticazione a due fattori', $s['twofactor_enabled'] );
					?>
				</tbody>
			</table>

			<h2>Attività recenti</h2>
			<table class="widefat striped">
				<thead><tr><th>Data</th><th>Tipo</th><th>Messaggio</th></tr></thead>
				<tbody>
				<?php if ( empty( $logs ) ) : ?>
					<tr><td colspan="3">Nessun evento registrato.</td></tr>
				<?php else : foreach ( $logs as $l ) : ?>
					<tr>
						<td><?php echo esc_html( $l->created_at ); ?></td>
						<td><span class="sg-sev sg-sev-<?php echo esc_attr( $l->severity ); ?>"><?php echo esc_html( $l->event_type ); ?></span></td>
						<td><?php echo esc_html( $l->message ); ?></td>
					</tr>
				<?php endforeach; endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	private function status_row( $label, $on ) {
		printf(
			'<tr><td>%s</td><td style="text-align:right">%s</td></tr>',
			esc_html( $label ),
			$on ? '<span class="sg-badge sg-badge-on">Attivo</span>' : '<span class="sg-badge sg-badge-off">Spento</span>'
		);
	}

	/**
	 * Stampa un'etichetta colorata per il livello di criticità.
	 */
	private function crit_badge( $severity ) {
		$map = array(
			'alta'  => array( 'Alta', 'sg-crit-alta' ),
			'media' => array( 'Media', 'sg-crit-media' ),
			'bassa' => array( 'Bassa', 'sg-crit-bassa' ),
		);
		$s = isset( $map[ $severity ] ) ? $map[ $severity ] : $map['media'];
		printf( '<span class="sg-crit %s">%s</span>', esc_attr( $s[1] ), esc_html( $s[0] ) );
	}

	private function crit_legend() {
		?>
		<p class="sg-legend">
			<span class="sg-crit sg-crit-alta">Alta</span> intervieni subito &nbsp;
			<span class="sg-crit sg-crit-media">Media</span> da verificare &nbsp;
			<span class="sg-crit sg-crit-bassa">Bassa</span> informativo
		</p>
		<?php
	}

	public function page_scanner() {
		$last = $this->guardian->scanner->get_last_scan();
		?>
		<div class="wrap sg-wrap">
			<h1>Scansione</h1>
			<?php $this->notice(); ?>

			<p>La scansione confronta i file del core di WordPress con quelli ufficiali e cerca codice sospetto in temi, plugin e uploads.</p>
			<p>
				<button id="sg-scan-btn" class="button button-primary button-hero">Avvia scansione completa</button>
				<span id="sg-scan-status"></span>
			</p>

			<?php if ( ! empty( $last['core_error'] ) ) : ?>
				<div class="notice notice-warning"><p>Scansione core: <?php echo esc_html( $last['core_error'] ); ?></p></div>
			<?php endif; ?>

			<?php if ( ! empty( $last['threats'] ) ) : ?>
				<?php
				$has_quar = false;
				foreach ( $last['threats'] as $t ) {
					if ( $this->is_quarantinable( $t ) ) {
						$has_quar = true;
						break;
					}
				}
				?>
				<h2>Risultati (<?php echo count( $last['threats'] ); ?>)</h2>
				<?php $this->crit_legend(); ?>
				<table class="widefat striped sg-results">
					<thead><tr>
						<td class="check-column"><?php if ( $has_quar ) : ?><input type="checkbox" id="sg-select-all" title="Seleziona tutti"><?php endif; ?></td>
						<th>Criticità</th><th>File</th><th>Motivo e come proteggersi</th><th>Azione</th>
					</tr></thead>
					<tbody>
					<?php foreach ( $last['threats'] as $t ) : ?>
						<tr>
							<td class="check-column">
								<?php if ( $this->is_quarantinable( $t ) ) : ?>
									<input type="checkbox" class="sg-pick" value="<?php echo esc_attr( $this->quar_path( $t ) ); ?>">
								<?php endif; ?>
							</td>
							<td><?php $this->crit_badge( $t['severity'] ?? 'media' ); ?></td>
							<td><code><?php echo esc_html( $t['file'] ); ?></code></td>
							<td>
								<strong><?php echo esc_html( $t['reason'] ); ?></strong>
								<?php if ( ! empty( $t['detail'] ) ) : ?><br><span class="sg-detail"><?php echo esc_html( $t['detail'] ); ?></span><?php endif; ?>
							</td>
							<td><?php $this->threat_action( $t ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>

				<?php if ( $has_quar ) : ?>
				<p class="sg-bulk-bar">
					<label><input type="checkbox" id="sg-select-all-2"> Seleziona tutti</label>
					<button type="button" class="button button-primary" id="sg-bulk-quar">Metti in quarantena i selezionati (<span id="sg-pick-count">0</span>)</button>
				</p>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="sg-bulk-form" style="display:none">
					<?php wp_nonce_field( 'sg_action' ); ?>
					<input type="hidden" name="action" value="sg_action">
					<input type="hidden" name="sg_do" value="bulk_quarantine">
					<input type="hidden" name="_back" value="security-guardian-scanner">
					<span id="sg-bulk-fields"></span>
				</form>
				<?php endif; ?>

				<p class="description">Suggerimento: prima di eliminare, metti in quarantena. Se il sito continua a funzionare, elimina definitivamente dalla pagina Quarantena. I file del core si riportano invece all'originale con "Ripristina originale".</p>
			<?php elseif ( ! empty( $last['scanned_at'] ) ) : ?>
				<div class="notice notice-success"><p>Nessuna minaccia trovata nell'ultima scansione del <?php echo esc_html( $last['scanned_at'] ); ?>.</p></div>
			<?php endif; ?>
		</div>
		<?php
	}

	/** Il tipo di elemento può essere messo in quarantena? */
	private function is_quarantinable( $t ) {
		return in_array( $t['type'], array( 'heuristic', 'uploads_php', 'core_unknown' ), true );
	}

	/** Percorso assoluto da usare per la quarantena di un elemento. */
	private function quar_path( $t ) {
		return ( 'core_unknown' === $t['type'] ) ? ABSPATH . $t['file'] : $t['file'];
	}

	private function threat_action( $t ) {
		$back = 'security-guardian-scanner';
		if ( 'core_modified' === $t['type'] ) {
			$this->action_button( 'restore_core', 'Ripristina originale', array( 'file' => $t['file'] ), $back, 'button-primary' );
		} elseif ( $this->is_quarantinable( $t ) ) {
			$this->action_button( 'quarantine', 'Metti in quarantena', array( 'file' => $this->quar_path( $t ) ), $back );
		} else {
			echo '—';
		}
	}

	private function action_button( $do, $label, $fields, $back, $class = 'button' ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
			<?php wp_nonce_field( 'sg_action' ); ?>
			<input type="hidden" name="action" value="sg_action">
			<input type="hidden" name="sg_do" value="<?php echo esc_attr( $do ); ?>">
			<input type="hidden" name="_back" value="<?php echo esc_attr( $back ); ?>">
			<?php foreach ( $fields as $k => $v ) : ?>
				<input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>">
			<?php endforeach; ?>
			<button type="submit" class="button <?php echo esc_attr( $class ); ?>"><?php echo esc_html( $label ); ?></button>
		</form>
		<?php
	}

	public function page_database() {
		$last = $this->guardian->db_scanner->get_last_scan();
		$quar = $this->guardian->db_scanner->get_quarantine();
		?>
		<div class="wrap sg-wrap">
			<h1>Scansione del database</h1>
			<?php $this->notice(); ?>
			<p>Cerca codice iniettato (script, iframe, offuscamenti) in articoli, opzioni e commenti. La pulizia rimuove solo i blocchi pericolosi e salva sempre l'originale, così puoi ripristinarlo.</p>
			<p>
				<button id="sg-db-scan-btn" class="button button-primary button-hero">Avvia scansione del database</button>
				<span id="sg-db-scan-status"></span>
			</p>

			<?php if ( ! empty( $last['findings'] ) ) : ?>
				<h2>Elementi sospetti (<?php echo count( $last['findings'] ); ?>)</h2>
				<?php $this->crit_legend(); ?>
				<table class="widefat striped sg-results">
					<thead><tr>
						<td class="check-column"><input type="checkbox" id="sg-select-all-db" title="Seleziona tutti"></td>
						<th>Criticità</th><th>Posizione</th><th>Motivo e come proteggersi</th><th>Estratto</th><th>Azione</th>
					</tr></thead>
					<tbody>
					<?php foreach ( $last['findings'] as $f ) : ?>
						<tr>
							<td class="check-column">
								<input type="checkbox" class="sg-pick-db" value="<?php echo esc_attr( $f['source'] . '|' . $f['id'] ); ?>">
							</td>
							<td><?php $this->crit_badge( $f['severity'] ?? 'media' ); ?></td>
							<td><?php echo esc_html( $f['label'] ); ?></td>
							<td>
								<strong><?php echo esc_html( $f['reason'] ); ?></strong>
								<?php if ( ! empty( $f['detail'] ) ) : ?><br><span class="sg-detail"><?php echo esc_html( $f['detail'] ); ?></span><?php endif; ?>
							</td>
							<td><code style="font-size:11px"><?php echo esc_html( $f['snippet'] ); ?></code></td>
							<td><?php $this->action_button( 'db_clean', 'Pulisci', array( 'source' => $f['source'], 'id' => $f['id'] ), 'security-guardian-database' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>

				<p class="sg-bulk-bar">
					<label><input type="checkbox" id="sg-select-all-db-2"> Seleziona tutti</label>
					<button type="button" class="button button-primary" id="sg-bulk-clean">Pulisci i selezionati (<span id="sg-pick-count-db">0</span>)</button>
				</p>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="sg-bulk-form-db" style="display:none">
					<?php wp_nonce_field( 'sg_action' ); ?>
					<input type="hidden" name="action" value="sg_action">
					<input type="hidden" name="sg_do" value="bulk_clean">
					<input type="hidden" name="_back" value="security-guardian-database">
					<span id="sg-bulk-fields-db"></span>
				</form>

				<p class="description">Attenzione: se un articolo contiene uno script legittimo (es. un embed), la pulizia lo rimuove. Puoi sempre ripristinarlo dalla tabella della quarantena del database, qui sotto.</p>
			<?php elseif ( ! empty( $last['scanned_at'] ) ) : ?>
				<div class="notice notice-success"><p>Nessun elemento sospetto nel database (scansione del <?php echo esc_html( $last['scanned_at'] ); ?>).</p></div>
			<?php endif; ?>

			<?php if ( ! empty( $quar ) ) : ?>
				<h2>Quarantena del database</h2>
				<table class="widefat striped">
					<thead><tr><th>Origine</th><th>Elemento</th><th>Data</th><th>Azione</th></tr></thead>
					<tbody>
					<?php foreach ( $quar as $key => $item ) : ?>
						<tr>
							<td><?php echo esc_html( $item['source'] ); ?></td>
							<td><?php echo esc_html( $item['id'] ); ?></td>
							<td><?php echo esc_html( $item['date'] ); ?></td>
							<td><?php $this->action_button( 'db_restore', 'Ripristina originale', array( 'key' => $key ), 'security-guardian-database' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	public function page_2fa() {
		$tf      = $this->guardian->two_factor;
		$user    = wp_get_current_user();
		$uid     = $user->ID;
		$enabled = $tf->is_enabled( $uid );
		$pending = $tf->get_pending_secret( $uid );
		$codes   = get_transient( 'sg_2fa_codes_' . $uid );
		if ( $codes ) {
			delete_transient( 'sg_2fa_codes_' . $uid );
		}
		?>
		<div class="wrap sg-wrap">
			<h1>Autenticazione a due fattori</h1>
			<?php $this->notice(); ?>

			<?php if ( ! $tf->user_eligible( $uid ) ) : ?>
				<div class="notice notice-info inline"><p>La verifica a due fattori non è richiesta per il tuo ruolo su questo sito. Un amministratore può cambiare i ruoli interessati in <a href="<?php echo esc_url( admin_url( 'admin.php?page=security-guardian-settings' ) ); ?>">Impostazioni</a>.</p></div>
			</div>
			<?php
			return;
			endif;
			?>

			<?php if ( $codes ) : ?>
				<div class="sg-backup-box">
					<h2>Codici di backup — salvali adesso</h2>
					<p>Servono se perdi il telefono. Ognuno è usabile una sola volta. Non verranno più mostrati.</p>
					<ul class="sg-codes">
						<?php foreach ( $codes as $c ) : ?><li><code><?php echo esc_html( $c ); ?></code></li><?php endforeach; ?>
					</ul>
				</div>
			<?php endif; ?>

			<?php if ( $enabled ) : ?>
				<div class="notice notice-success inline"><p><strong>La 2FA è attiva</strong> per il tuo account (<?php echo esc_html( $user->user_login ); ?>). Codici di backup rimasti: <?php echo intval( $tf->count_backup_codes( $uid ) ); ?>.</p></div>
				<p>Al prossimo accesso ti verrà chiesto il codice dell'app insieme a utente e password.</p>
				<p>
					<?php $this->action_button( '2fa_regen', 'Rigenera codici di backup', array(), 'security-guardian-2fa' ); ?>
					<?php $this->action_button( '2fa_disable', 'Disattiva 2FA', array(), 'security-guardian-2fa', 'sg-btn-danger' ); ?>
				</p>

			<?php elseif ( $pending ) : ?>
				<h2>Passo 1 — Aggiungi l'account alla tua app</h2>
				<p>Apri Google Authenticator, Authy, Microsoft Authenticator o 1Password e scegli <em>Aggiungi / Inserisci chiave di configurazione</em>. Inserisci questa chiave:</p>
				<p class="sg-secret"><code><?php echo esc_html( $tf->format_secret( $pending ) ); ?></code></p>
				<p class="description">Tipo: a tempo (TOTP) · 6 cifre · 30 secondi.</p>
				<details>
					<summary>Oppure usa il link otpauth:// (per chi sa importarlo)</summary>
					<p><code style="word-break:break-all"><?php echo esc_html( $tf->get_otpauth_uri( $pending, $user ) ); ?></code></p>
				</details>

				<h2>Passo 2 — Conferma</h2>
				<p>Inserisci il codice a 6 cifre che vedi ora nell'app:</p>
				<div style="display:flex;align-items:flex-start;gap:8px">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
						<?php wp_nonce_field( 'sg_action' ); ?>
						<input type="hidden" name="action" value="sg_action">
						<input type="hidden" name="sg_do" value="2fa_confirm">
						<input type="hidden" name="_back" value="security-guardian-2fa">
						<input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="123456" class="regular-text" style="max-width:140px" required>
						<button type="submit" class="button button-primary">Attiva 2FA</button>
					</form>
					<?php $this->action_button( '2fa_cancel', 'Annulla', array(), 'security-guardian-2fa' ); ?>
				</div>

			<?php else : ?>
				<p>La verifica a due fattori aggiunge un codice temporaneo generato dal tuo telefono, oltre alla password. Anche se qualcuno ruba la password, senza il telefono non entra.</p>
				<p>Ti serve un'app gratuita: Google Authenticator, Authy, Microsoft Authenticator o 1Password.</p>
				<?php if ( empty( $this->guardian->get_settings()['twofactor_enabled'] ) ) : ?>
					<div class="notice notice-warning inline"><p>La 2FA è spenta a livello di sito. Attivala prima in <a href="<?php echo esc_url( admin_url( 'admin.php?page=security-guardian-settings' ) ); ?>">Impostazioni</a>, altrimenti il codice non verrà richiesto al login.</p></div>
				<?php endif; ?>
				<?php $this->action_button( '2fa_start', 'Configura la 2FA per il mio account', array(), 'security-guardian-2fa', 'button-primary button-hero' ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	public function page_quarantine() {
		$index = $this->guardian->quarantine->get_index();
		?>
		<div class="wrap sg-wrap">
			<h1>Quarantena</h1>
			<?php $this->notice(); ?>
			<p>I file qui dentro sono isolati e non eseguibili. Ripristinali se erano falsi positivi, altrimenti eliminali.</p>
			<table class="widefat striped">
				<thead><tr><th>File originale</th><th>Data</th><th>Note</th><th>Azioni</th></tr></thead>
				<tbody>
				<?php if ( empty( $index ) ) : ?>
					<tr><td colspan="4">La quarantena è vuota.</td></tr>
				<?php else : foreach ( $index as $id => $info ) : ?>
					<tr>
						<td><code><?php echo esc_html( $info['original'] ); ?></code></td>
						<td><?php echo esc_html( $info['date'] ); ?></td>
						<td><?php echo esc_html( $info['note'] ?? '' ); ?></td>
						<td>
							<?php
							$this->action_button( 'q_restore', 'Ripristina', array( 'qid' => $id ), 'security-guardian-quarantine' );
							$this->action_button( 'q_delete', 'Elimina', array( 'qid' => $id ), 'security-guardian-quarantine', 'sg-btn-danger' );
							?>
						</td>
					</tr>
				<?php endforeach; endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	public function page_log() {
		$logs = $this->guardian->logger->get_recent( 200 );
		?>
		<div class="wrap sg-wrap">
			<h1>Registro attività</h1>
			<?php $this->notice(); ?>
			<?php $this->action_button( 'clear_log', 'Svuota registro', array(), 'security-guardian-log', 'sg-btn-danger' ); ?>
			<table class="widefat striped" style="margin-top:12px">
				<thead><tr><th>Data</th><th>Gravità</th><th>Tipo</th><th>IP</th><th>Messaggio</th></tr></thead>
				<tbody>
				<?php if ( empty( $logs ) ) : ?>
					<tr><td colspan="5">Nessun evento.</td></tr>
				<?php else : foreach ( $logs as $l ) : ?>
					<tr>
						<td><?php echo esc_html( $l->created_at ); ?></td>
						<td><span class="sg-sev sg-sev-<?php echo esc_attr( $l->severity ); ?>"><?php echo esc_html( $l->severity ); ?></span></td>
						<td><?php echo esc_html( $l->event_type ); ?></td>
						<td><?php echo esc_html( $l->ip ); ?></td>
						<td><?php echo esc_html( $l->message ); ?></td>
					</tr>
				<?php endforeach; endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	public function page_settings() {
		$s = $this->guardian->get_settings();
		?>
		<div class="wrap sg-wrap">
			<h1>Impostazioni</h1>
			<?php $this->notice(); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'sg_action' ); ?>
				<input type="hidden" name="action" value="sg_action">
				<input type="hidden" name="sg_do" value="save_settings">
				<input type="hidden" name="_back" value="security-guardian-settings">

				<h2>Protezione</h2>
				<table class="form-table">
					<?php
					$this->checkbox_row( 'firewall_enabled', 'Firewall applicativo', $s );
					$this->checkbox_row( 'brute_force_enabled', 'Protezione brute force sul login', $s );
					?>
					<tr>
						<th>Tentativi massimi di login</th>
						<td><input type="number" min="1" name="max_login_attempts" value="<?php echo esc_attr( $s['max_login_attempts'] ); ?>"></td>
					</tr>
					<tr>
						<th>Minuti di blocco</th>
						<td><input type="number" min="1" name="lockout_minutes" value="<?php echo esc_attr( $s['lockout_minutes'] ); ?>"></td>
					</tr>
				</table>

				<h2>Indurimento</h2>
				<table class="form-table">
					<?php
					$this->checkbox_row( 'hardening_xmlrpc', 'Disattiva XML-RPC', $s );
					$this->checkbox_row( 'hardening_enum', 'Blocca enumerazione utenti', $s );
					$this->checkbox_row( 'hardening_headers', 'Aggiungi header di sicurezza', $s );
					$this->checkbox_row( 'hardening_file_editor', 'Disattiva editor file nel pannello', $s );
					$this->checkbox_row( 'hardening_hide_version', 'Nascondi versione di WordPress', $s );
					?>
				</table>

				<h2>Autenticazione a due fattori</h2>
				<table class="form-table">
					<?php $this->checkbox_row( 'twofactor_enabled', 'Abilita la 2FA sul sito (ogni utente la attiva dal proprio account)', $s ); ?>
					<tr>
						<th>Ruoli a cui si applica</th>
						<td>
							<?php
							$selected_roles = isset( $s['twofactor_roles'] ) && is_array( $s['twofactor_roles'] ) ? $s['twofactor_roles'] : array( 'administrator' );
							$all_roles      = function_exists( 'wp_roles' ) ? wp_roles()->get_names() : array( 'administrator' => 'Administrator' );
							foreach ( $all_roles as $role_key => $role_name ) {
								printf(
									'<label style="display:inline-block;min-width:200px;margin:2px 0"><input type="checkbox" name="twofactor_roles[]" value="%s" %s> %s</label>',
									esc_attr( $role_key ),
									checked( in_array( $role_key, $selected_roles, true ), true, false ),
									esc_html( $role_name )
								);
							}
							?>
							<p class="description">Solo gli utenti con uno di questi ruoli potranno attivare la 2FA e la vedranno richiesta al login. Es.: Amministratore ed Editore, ma non Cliente o Sottoscrittore.</p>
						</td>
					</tr>
				</table>

				<h2>Scansione e notifiche</h2>
				<table class="form-table">
					<tr>
						<th>Frequenza scansione automatica</th>
						<td>
							<select name="scan_schedule">
								<?php
								$opts = array( 'hourly' => 'Ogni ora', 'twicedaily' => 'Due volte al giorno', 'daily' => 'Ogni giorno', 'none' => 'Mai (solo manuale)' );
								foreach ( $opts as $k => $label ) {
									printf( '<option value="%s" %s>%s</option>', esc_attr( $k ), selected( $s['scan_schedule'], $k, false ), esc_html( $label ) );
								}
								?>
							</select>
						</td>
					</tr>
					<?php $this->checkbox_row( 'notify_enabled', 'Invia email quando trovo minacce', $s ); ?>
					<tr>
						<th>Email per le notifiche</th>
						<td><input type="email" class="regular-text" name="notify_email" value="<?php echo esc_attr( $s['notify_email'] ); ?>"></td>
					</tr>
				</table>

				<?php submit_button( 'Salva impostazioni' ); ?>
			</form>

			<hr>
			<h2>Aggiornamenti</h2>
			<?php $u = $this->guardian->updater->status(); ?>
			<table class="form-table">
				<tr>
					<th>Versione installata</th>
					<td><code><?php echo esc_html( $u['installed'] ); ?></code></td>
				</tr>
				<tr>
					<th>Ultima versione disponibile</th>
					<td>
						<?php if ( $u['latest'] ) : ?>
							<code><?php echo esc_html( $u['latest'] ); ?></code>
							<?php if ( $u['update_available'] ) : ?>
								<span class="sg-badge sg-badge-off" style="margin-left:8px">Aggiornamento disponibile</span>
								&nbsp;<a href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>">Vai alla pagina Plugin per aggiornare</a>
							<?php else : ?>
								<span class="sg-badge sg-badge-on" style="margin-left:8px">Sei aggiornato</span>
							<?php endif; ?>
						<?php else : ?>
							<em>Nessuna release trovata su GitHub (ancora).</em>
						<?php endif; ?>
					</td>
				</tr>
			</table>
			<?php $this->action_button( 'check_updates', 'Controlla aggiornamenti ora', array(), 'security-guardian-settings' ); ?>
			<p class="description">Gli aggiornamenti arrivano dalle release del repository GitHub. Quando pubblichi una nuova release con versione più alta, WordPress mostrerà "Aggiornamento disponibile" nella pagina Plugin, come per qualsiasi altro plugin.</p>
		</div>
		<?php
	}

	private function checkbox_row( $key, $label, $s ) {
		printf(
			'<tr><th>%s</th><td><label><input type="checkbox" name="%s" value="1" %s> Attivo</label></td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			checked( ! empty( $s[ $key ] ), true, false )
		);
	}
}
