<?php
/**
 * Aggiornatore da GitHub.
 *
 * Collega il plugin al sistema di aggiornamenti di WordPress: controlla
 * l'ultima release pubblicata sul repository GitHub e, se è più recente
 * di quella installata, fa comparire "Aggiornamento disponibile" nella
 * pagina Plugin. L'aggiornamento si installa con un clic, come per
 * qualsiasi altro plugin.
 *
 * Non serve wordpress.org: le versioni arrivano dalle release del repo.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Updater {

	private $owner;
	private $repo;
	private $basename;   // es. wp-security-guardian/wp-security-guardian.php
	private $slug;       // es. wp-security-guardian
	private $version;

	const CACHE_KEY = 'sg_update_info';
	const CACHE_TTL = 6 * HOUR_IN_SECONDS;

	public function __construct( $owner, $repo, $basename, $version ) {
		$this->owner    = $owner;
		$this->repo     = $repo;
		$this->basename = $basename;
		$this->slug     = dirname( $basename );
		$this->version  = $version;
	}

	public function boot() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugins_api' ), 10, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_source_dir' ), 10, 4 );
		// Link "Controlla aggiornamenti" nella riga del plugin.
		add_filter( 'plugin_action_links_' . $this->basename, array( $this, 'action_link' ) );
	}

	private function repo_url() {
		return 'https://github.com/' . $this->owner . '/' . $this->repo;
	}

	/**
	 * Scarica (con cache) le informazioni sull'ultima release.
	 *
	 * @return object|false
	 */
	public function get_remote_info( $force = false ) {
		if ( ! $force ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( false !== $cached ) {
				return empty( $cached ) ? false : $cached;
			}
		}

		$url      = sprintf( 'https://api.github.com/repos/%s/%s/releases/latest', $this->owner, $this->repo );
		$response = wp_remote_get( $url, array(
			'timeout' => 15,
			'headers' => array(
				'Accept'     => 'application/vnd.github+json',
				'User-Agent' => 'Security-Guardian-Updater',
			),
		) );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			// Nessuna release o errore: cache vuota per non martellare l'API.
			set_transient( self::CACHE_KEY, '', self::CACHE_TTL );
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ) );
		if ( ! is_object( $data ) || empty( $data->tag_name ) ) {
			set_transient( self::CACHE_KEY, '', self::CACHE_TTL );
			return false;
		}

		set_transient( self::CACHE_KEY, $data, self::CACHE_TTL );
		return $data;
	}

	private function remote_version( $remote ) {
		return ltrim( $remote->tag_name, 'vV' );
	}

	/**
	 * URL del pacchetto da installare: preferisce uno zip allegato alla
	 * release, altrimenti lo zip sorgente generato da GitHub.
	 */
	private function package_url( $remote ) {
		if ( ! empty( $remote->assets ) && is_array( $remote->assets ) ) {
			foreach ( $remote->assets as $asset ) {
				if ( ! empty( $asset->browser_download_url ) && preg_match( '/\.zip$/i', $asset->name ) ) {
					return $asset->browser_download_url;
				}
			}
		}
		return isset( $remote->zipball_url ) ? $remote->zipball_url : '';
	}

	/**
	 * Inietta l'aggiornamento nel transient di WordPress.
	 */
	public function check_update( $transient ) {
		if ( empty( $transient ) || ! is_object( $transient ) ) {
			return $transient;
		}

		$remote = $this->get_remote_info();
		if ( ! $remote ) {
			return $transient;
		}

		$remote_version = $this->remote_version( $remote );
		$item_base      = array(
			'id'          => $this->repo_url(),
			'slug'        => $this->slug,
			'plugin'      => $this->basename,
			'new_version' => $remote_version,
			'url'         => $this->repo_url(),
			'package'     => $this->package_url( $remote ),
			'icons'       => array(),
			'banners'     => array(),
			'tested'      => get_bloginfo( 'version' ),
			'requires_php'=> '7.4',
		);

		if ( version_compare( $remote_version, $this->version, '>' ) ) {
			$transient->response[ $this->basename ] = (object) $item_base;
		} else {
			// Segnala "nessun aggiornamento" (così WP non interroga wordpress.org).
			$item_base['new_version'] = $this->version;
			$transient->no_update[ $this->basename ] = (object) $item_base;
		}

		return $transient;
	}

	/**
	 * Popolo la finestra "Visualizza dettagli / changelog".
	 */
	public function plugins_api( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}
		if ( empty( $args->slug ) || $args->slug !== $this->slug ) {
			return $result;
		}
		$remote = $this->get_remote_info();
		if ( ! $remote ) {
			return $result;
		}

		return (object) array(
			'name'          => 'Security Guardian',
			'slug'          => $this->slug,
			'version'       => $this->remote_version( $remote ),
			'author'        => '<a href="' . esc_url( $this->repo_url() ) . '">Giovanni</a>',
			'homepage'      => $this->repo_url(),
			'requires'      => '5.6',
			'requires_php'  => '7.4',
			'download_link' => $this->package_url( $remote ),
			'last_updated'  => isset( $remote->published_at ) ? $remote->published_at : '',
			'sections'      => array(
				'description' => 'Plugin di sicurezza per WordPress: protezione, scanner del core e del database, quarantena, ripristino e 2FA.',
				'changelog'   => $this->format_changelog( isset( $remote->body ) ? $remote->body : '' ),
			),
		);
	}

	private function format_changelog( $body ) {
		$body = wp_kses_post( $body );
		// Converte le righe che iniziano con "- " in elenco puntato.
		$lines = preg_split( '/\r\n|\r|\n/', $body );
		$out   = '';
		$in_ul = false;
		foreach ( $lines as $line ) {
			if ( preg_match( '/^\s*[-*]\s+(.*)$/', $line, $m ) ) {
				if ( ! $in_ul ) {
					$out  .= '<ul>';
					$in_ul = true;
				}
				$out .= '<li>' . esc_html( $m[1] ) . '</li>';
			} else {
				if ( $in_ul ) {
					$out  .= '</ul>';
					$in_ul = false;
				}
				if ( '' !== trim( $line ) ) {
					$out .= '<p>' . esc_html( $line ) . '</p>';
				}
			}
		}
		if ( $in_ul ) {
			$out .= '</ul>';
		}
		return $out;
	}

	/**
	 * Rinomina la cartella estratta con lo slug corretto del plugin.
	 * Necessario quando l'aggiornamento usa lo zip sorgente di GitHub
	 * (che si estrae come "security-guardian-<tag>" invece di "<slug>").
	 */
	public function fix_source_dir( $source, $remote_source, $upgrader, $hook_extra = array() ) {
		global $wp_filesystem;

		// Interveniamo solo sul nostro plugin.
		$is_ours = ( isset( $hook_extra['plugin'] ) && $hook_extra['plugin'] === $this->basename );
		if ( ! $is_ours ) {
			// In fallback: riconosci la cartella dal nome del repo.
			if ( false === strpos( basename( untrailingslashit( $source ) ), $this->repo ) ) {
				return $source;
			}
		}

		if ( ! $wp_filesystem ) {
			return $source;
		}

		$desired = trailingslashit( $remote_source ) . $this->slug;
		$source  = untrailingslashit( $source );

		if ( $source === untrailingslashit( $desired ) ) {
			return trailingslashit( $source );
		}
		if ( $wp_filesystem->move( $source, $desired, true ) ) {
			return trailingslashit( $desired );
		}
		return trailingslashit( $source );
	}

	public function action_link( $links ) {
		$url = wp_nonce_url(
			admin_url( 'admin-post.php?action=sg_action&sg_do=check_updates&_back=plugins' ),
			'sg_action'
		);
		$links['sg_check'] = '<a href="' . esc_url( $url ) . '">Controlla aggiornamenti</a>';
		return $links;
	}

	/** Forza un nuovo controllo: svuota la cache e il transient di WP. */
	public function force_check() {
		delete_transient( self::CACHE_KEY );
		delete_site_transient( 'update_plugins' );
		$this->get_remote_info( true );
	}

	/**
	 * Info sincrona per la schermata Impostazioni.
	 *
	 * @return array {installed, latest, update_available}
	 */
	public function status() {
		$remote = $this->get_remote_info();
		$latest = $remote ? $this->remote_version( $remote ) : '';
		return array(
			'installed'        => $this->version,
			'latest'           => $latest,
			'update_available' => $latest && version_compare( $latest, $this->version, '>' ),
		);
	}
}
