<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'PinkFlamingo502' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'R8T#/yV(QKCZV<-kvM6-.(Y5bVbydYBFS_q.*h61Qq}9TanP%m:&@+Z/p_~.Y#gQ');
define('SECURE_AUTH_KEY',  'JZ{Z|Ly(AQ`r7-,4npqx@v06u!$QDw7:<@n1NT>OD{C=II4^dRJ#{6c*jZ)tz_r(');
define('LOGGED_IN_KEY',    '&LbsPV^^<!$U+;>aMp|)8D9ow_0<H6160{n@wFxV@V/2Q )]m+aqwH+~|:]>y-SN');
define('NONCE_KEY',        ',B]Qn]K> --./N7+3ch.8U+rMgeK@~e|@TH#Q&KOw-eL <eQ6}@<NzSGV%zm AnX');
define('AUTH_SALT',        'y1*`/UTwa$)/5bll*V`@s!kLu-QK,JWsySQe4bg*_6fS:gYMpj0K+I(?D6S9iD>{');
define('SECURE_AUTH_SALT', '?`p3jlO1N^=6k]6iS6ik`ug$C i Tf.E}DuW:-`btl=Le-|+Z.5B%v$rna;M6C&D');
define('LOGGED_IN_SALT',   'A>+a`|*WWz( gL)Z+M2 OJw/x0<eDO<[rJ6HwDYgh)u[cPxP|&BK7?Q%!wxkDL*H');
define('NONCE_SALT',       '_&?)IGP]^FA2|7.M=TU;<xQMJg@b+tt<Q*-UfQ-V4hcmF:dUnG5O)7+63Uzct5z,');

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
