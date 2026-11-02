<?php
/**
 * Lista degli elementi "ignorati" (whitelist).
 *
 * Quando un elemento segnalato è un falso positivo (es. uno script di
 * Google Analytics inserito volutamente, una mappa in una pagina Contatti,
 * il codice di un plugin), l'utente può marcarlo come sicuro: smette di
 * comparire nei risultati e nelle email di notifica.
 *
 * L'impronta (fingerprint) include la POSIZIONE e il CONTENUTO attuale:
 * se quel file o quel contenuto cambia in futuro (es. viene infettato),
 * l'impronta cambia e l'elemento torna a essere segnalato.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SG_Whitelist {

	const OPTION = 'sg_ignored';

	/**
	 * Tutti gli elementi ignorati: array( fingerprint => array(label, kind, date) ).
	 */
	public static function all() {
		$list = get_option( self::OPTION, array() );
		return is_array( $list ) ? $list : array();
	}

	public static function is_ignored( $fp ) {
		$fp = (string) $fp;
		if ( '' === $fp ) {
			return false;
		}
		$list = self::all();
		return isset( $list[ $fp ] );
	}

	/**
	 * Aggiunge un elemento alla whitelist.
	 *
	 * @param string $fp    Impronta (32 caratteri esadecimali).
	 * @param string $label Testo leggibile per la gestione.
	 * @param string $kind  'file' | 'db'.
	 */
	public static function ignore( $fp, $label = '', $kind = '' ) {
		$fp = self::sanitize_fp( $fp );
		if ( '' === $fp ) {
			return false;
		}
		$list        = self::all();
		$list[ $fp ] = array(
			'label' => (string) $label,
			'kind'  => (string) $kind,
			'date'  => current_time( 'mysql' ),
		);
		update_option( self::OPTION, $list, false );
		return true;
	}

	/**
	 * Rimuove un elemento dalla whitelist (torna a essere segnalato).
	 */
	public static function unignore( $fp ) {
		$fp   = self::sanitize_fp( $fp );
		$list = self::all();
		if ( isset( $list[ $fp ] ) ) {
			unset( $list[ $fp ] );
			update_option( self::OPTION, $list, false );
			return true;
		}
		return false;
	}

	/**
	 * Impronta di un elemento del database (posizione + contenuto).
	 */
	public static function db_fp( $source, $id, $content ) {
		return md5( 'db|' . $source . '|' . $id . '|' . (string) $content );
	}

	/**
	 * Impronta di un file (percorso + contenuto attuale).
	 */
	public static function file_fp( $file, $type = '' ) {
		$path  = wp_normalize_path( (string) $file );
		$abs   = file_exists( $path ) ? $path : ABSPATH . ltrim( $path, '/' );
		$chash = is_readable( $abs ) ? md5_file( $abs ) : '0';
		return md5( 'file|' . $path . '|' . $chash );
	}

	/**
	 * Restituisce i soli elementi NON ignorati.
	 * Ogni elemento deve contenere la chiave 'fp'.
	 */
	public static function filter( $items ) {
		if ( empty( $items ) || ! is_array( $items ) ) {
			return array();
		}
		$ignored = self::all();
		if ( empty( $ignored ) ) {
			return array_values( $items );
		}
		$out = array();
		foreach ( $items as $it ) {
			$fp = isset( $it['fp'] ) ? $it['fp'] : '';
			if ( '' !== $fp && isset( $ignored[ $fp ] ) ) {
				continue;
			}
			$out[] = $it;
		}
		return $out;
	}

	/**
	 * Elementi ignorati di un certo tipo ('file' | 'db').
	 */
	public static function by_kind( $kind ) {
		$rows = array();
		foreach ( self::all() as $fp => $meta ) {
			if ( isset( $meta['kind'] ) && $meta['kind'] === $kind ) {
				$rows[ $fp ] = $meta;
			}
		}
		return $rows;
	}

	private static function sanitize_fp( $fp ) {
		return preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $fp ) );
	}
}
