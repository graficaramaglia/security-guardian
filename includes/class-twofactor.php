<?php
/**
 * Autenticazione a due fattori (2FA) basata su TOTP (RFC 6238),
 * compatibile con Google Authenticator, Authy, Microsoft Authenticator,
 * 1Password e simili.
 *
 * Nessuna dipendenza esterna: la chiave si inserisce nell'app tramite
 * il codice di configurazione (chiave manuale) o il link otpauth://.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_TwoFactor {

	private $logger;

	const META_SECRET  = 'sg_2fa_secret';
	const META_ENABLED = 'sg_2fa_enabled';
	const META_PENDING = 'sg_2fa_pending';
	const META_BACKUP  = 'sg_2fa_backup';

	const DIGITS = 6;
	const PERIOD = 30;

	public function __construct( $logger ) {
		$this->logger = $logger;
	}

	public function boot() {
		// Verifica il secondo fattore dopo la password (priorità alta).
		add_filter( 'authenticate', array( $this, 'verify_second_factor' ), 50, 3 );
		// Mostra il campo del codice nel form di login.
		add_action( 'login_form', array( $this, 'render_login_field' ) );
	}

	/* ===================================================================
	 *  VERIFICA AL LOGIN
	 * =================================================================== */

	public function verify_second_factor( $user, $username, $password ) {
		// Se l'autenticazione precedente è fallita, lascia stare.
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		if ( ! $this->is_enabled( $user->ID ) ) {
			return $user;
		}

		$code = isset( $_POST['sg_2fa_code'] ) ? preg_replace( '/[^0-9a-zA-Z]/', '', wp_unslash( $_POST['sg_2fa_code'] ) ) : '';

		if ( '' === $code ) {
			return new WP_Error(
				'sg_2fa_required',
				__( '<strong>Verifica a due fattori:</strong> inserisci il codice dell\'app di autenticazione (insieme a utente e password).', 'security-guardian' )
			);
		}

		// Prima prova il codice TOTP.
		$secret = get_user_meta( $user->ID, self::META_SECRET, true );
		if ( $secret && $this->verify_totp( $secret, $code ) ) {
			return $user;
		}

		// Poi prova i codici di backup monouso.
		if ( $this->consume_backup_code( $user->ID, $code ) ) {
			$this->logger->log( '2fa_backup_used', 'Codice di backup usato per ' . $user->user_login, 'warning' );
			return $user;
		}

		$this->logger->log( '2fa_failed', 'Codice 2FA errato per ' . $user->user_login, 'warning' );
		return new WP_Error( 'sg_2fa_bad', __( 'Codice di verifica a due fattori non valido.', 'security-guardian' ) );
	}

	public function render_login_field() {
		?>
		<p class="sg-2fa-login">
			<label for="sg_2fa_code"><?php esc_html_e( 'Codice 2FA (se attivo)', 'security-guardian' ); ?><br>
				<input type="text" name="sg_2fa_code" id="sg_2fa_code" class="input" value="" autocomplete="one-time-code"
					inputmode="numeric" pattern="[0-9A-Za-z]*" placeholder="123456" />
			</label>
		</p>
		<?php
	}

	/* ===================================================================
	 *  GESTIONE PER UTENTE
	 * =================================================================== */

	public function is_enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/** Avvia la configurazione: genera un segreto "in attesa" di conferma. */
	public function start_setup( $user_id ) {
		$secret = $this->generate_secret();
		update_user_meta( $user_id, self::META_PENDING, $secret );
		return $secret;
	}

	public function get_pending_secret( $user_id ) {
		return get_user_meta( $user_id, self::META_PENDING, true );
	}

	/** Conferma la configurazione verificando un codice dall'app. */
	public function confirm_setup( $user_id, $code ) {
		$secret = $this->get_pending_secret( $user_id );
		if ( ! $secret ) {
			return new WP_Error( 'sg_no_pending', 'Nessuna configurazione in corso. Riprova.' );
		}
		$code = preg_replace( '/[^0-9]/', '', $code );
		if ( ! $this->verify_totp( $secret, $code ) ) {
			return new WP_Error( 'sg_bad_code', 'Codice non valido. Controlla l\'ora del telefono e riprova.' );
		}
		update_user_meta( $user_id, self::META_SECRET, $secret );
		update_user_meta( $user_id, self::META_ENABLED, 1 );
		delete_user_meta( $user_id, self::META_PENDING );

		$codes = $this->generate_backup_codes( $user_id );
		$this->logger->log( '2fa_enabled', '2FA attivata per ' . $this->user_label( $user_id ), 'info' );
		return $codes; // mostrati una sola volta
	}

	public function disable( $user_id ) {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_BACKUP );
		$this->logger->log( '2fa_disabled', '2FA disattivata per ' . $this->user_label( $user_id ), 'warning' );
		return true;
	}

	/** Annulla una configurazione in corso senza toccare una 2FA già attiva. */
	public function cancel_setup( $user_id ) {
		delete_user_meta( $user_id, self::META_PENDING );
		$this->logger->log( '2fa_setup_cancelled', 'Configurazione 2FA annullata per ' . $this->user_label( $user_id ), 'info' );
		return true;
	}

	/** Etichetta leggibile dell'utente (login), con fallback all'ID. */
	private function user_label( $user_id ) {
		$u = get_userdata( $user_id );
		return $u ? $u->user_login : ( 'user ID ' . $user_id );
	}

	public function get_otpauth_uri( $secret, $user ) {
		$issuer  = rawurlencode( get_bloginfo( 'name' ) ?: 'WordPress' );
		$account = rawurlencode( $user->user_login . '@' . wp_parse_url( home_url(), PHP_URL_HOST ) );
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			$issuer,
			$account,
			$secret,
			$issuer,
			self::DIGITS,
			self::PERIOD
		);
	}

	/** Raggruppa il segreto a blocchi di 4 per leggerlo più facilmente. */
	public function format_secret( $secret ) {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}

	/* ===================================================================
	 *  CODICI DI BACKUP
	 * =================================================================== */

	public function generate_backup_codes( $user_id, $count = 8 ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$code    = sprintf( '%04d-%04d', wp_rand( 0, 9999 ), wp_rand( 0, 9999 ) );
			$plain[] = $code;
			$hashed[] = wp_hash_password( str_replace( '-', '', $code ) );
		}
		update_user_meta( $user_id, self::META_BACKUP, $hashed );
		return $plain;
	}

	private function consume_backup_code( $user_id, $code ) {
		$code   = preg_replace( '/[^0-9]/', '', $code );
		$hashes = get_user_meta( $user_id, self::META_BACKUP, true );
		if ( empty( $hashes ) || ! is_array( $hashes ) ) {
			return false;
		}
		foreach ( $hashes as $i => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $hashes ) );
				return true;
			}
		}
		return false;
	}

	public function count_backup_codes( $user_id ) {
		$hashes = get_user_meta( $user_id, self::META_BACKUP, true );
		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	/* ===================================================================
	 *  MOTORE TOTP / HOTP  (RFC 6238 / RFC 4226)
	 * =================================================================== */

	public function generate_secret( $length_bytes = 20 ) {
		$random = random_bytes( $length_bytes );
		return $this->base32_encode( $random );
	}

	public function verify_totp( $secret, $code, $window = 1 ) {
		$code = preg_replace( '/[^0-9]/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$counter = (int) floor( time() / self::PERIOD );
		for ( $i = -$window; $i <= $window; $i++ ) {
			$expected = $this->hotp( $secret, $counter + $i );
			if ( hash_equals( $expected, $code ) ) {
				return true;
			}
		}
		return false;
	}

	private function hotp( $secret, $counter ) {
		$key = $this->base32_decode( $secret );
		// Contatore a 64 bit big-endian.
		$bin_counter = pack( 'N*', 0, $counter );
		$hash   = hash_hmac( 'sha1', $bin_counter, $key, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$part   = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
				| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
				| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
				| ( ord( $hash[ $offset + 3 ] ) & 0xff );
		$otp = $part % ( 10 ** self::DIGITS );
		return str_pad( (string) $otp, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/* ------------------------------ Base32 ------------------------------ */

	private function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$binary   = '';
		foreach ( str_split( $data ) as $char ) {
			$binary .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$chunks = str_split( $binary, 5 );
		$out    = '';
		foreach ( $chunks as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out  .= $alphabet[ bindec( $chunk ) ];
		}
		return $out;
	}

	private function base32_decode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$data     = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $data ) );
		$binary   = '';
		foreach ( str_split( $data ) as $char ) {
			$binary .= str_pad( decbin( strpos( $alphabet, $char ) ), 5, '0', STR_PAD_LEFT );
		}
		$bytes = str_split( $binary, 8 );
		$out   = '';
		foreach ( $bytes as $byte ) {
			if ( strlen( $byte ) === 8 ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}
}
