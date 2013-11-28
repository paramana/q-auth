<?php

/* !
 * Version: 1.0
 * Started: 21-10-2011
 * Updated: 28-11-2013
 *
 * Copyright (c) 2010 paramana.com
 *
 * Security functions
 * Many parts have been taken from wordpress source code
 *
 */

/**
 * Get the time-dependent variable for nonce creation.
 *
 * A nonce has a lifespan of two ticks. Nonces in their second tick may be
 * updated, e.g. by autosave.
 *
 * @since 2.5
 *
 * @return int
 */
function q_nonce_tick() {
    $nonce_life = 86400;

    return ceil(time() / ( $nonce_life / 2 ));
}

/**
 * Verify that correct nonce was used with time limit.
 *
 * The user is given an amount of time to use the token, so therefore, since the
 * UID and $action remain the same, the independent variable is the time.
 *
 * @since 2.0.3
 *
 * @param string|int $uid the user id to use in the nonce
 * @param string $nonce Nonce that was used in the form to verify
 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
 * @return bool Whether the nonce check passed or failed.
 */
function q_verify_nonce($uid, $nonce, $action = -1) {
    $uid = (int) $uid;

    $i = q_nonce_tick();

    // Nonce generated 0-12 hours ago
    if (substr(q_hash($i . $action . $uid, 'nonce'), -12, 10) == $nonce)
        return 1;
    // Nonce generated 12-24 hours ago
    if (substr(q_hash(($i - 1) . $action . $uid, 'nonce'), -12, 10) == $nonce)
        return 2;
    // Invalid nonce
    return false;
}

/**
 * Creates a random, one time use token.
 *
 * @since 2.0.3
 *
 * @param string|int $uid the user id to use in the nonce
 * @param string|int $action Scalar value to add context to the nonce.
 * @return string The one use form token
 */
function q_create_nonce($uid, $action = -1) {
    $uid = (int) $uid;

    $i = q_nonce_tick();

    return substr(q_hash($i . $action . $uid, 'nonce'), -12, 10);
}

/**
 * Generates a random password drawn from the defined set of characters.
 *
 * @param int $length The length of password to generate
 * @param bool $special_chars Whether to include standard special characters
 * @return string The random password
 * */
function generate_password($length = 12, $special_chars = true) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    if ($special_chars)
        $chars .= '!@#$%^&*()';

    $password = '';
    for ($i = 0; $i < $length; $i++)
        $password .= substr($chars, rand(0, strlen($chars) - 1), 1);
    return $password;
}

/**
 * Create a hash (encrypt) of a plain text password.
 *
 * For integration with other applications, this function can be overwritten to
 * instead use the other package password checking algorithm.
 *
 * @since 2.5
 * @global object $q_hasher PHPass object
 * @uses PasswordHash::HashPassword
 *
 * @param string $password Plain text user password to hash (should be alredy md5)
 * @return string The hash string of the password
 */
function q_hash_password($password) {
    global $q_hasher;

    if (empty($q_hasher)) {
        require_once( APP_ROOT . '/common/classes/phpass.class.php');
        $q_hasher = new PasswordHash(8, FALSE);
    }

    return $q_hasher->HashPassword($password);
}

/**
 * Get hash of given string.
 *
 * @since 2.0.3
 * @uses q_salt() Get WordPress salt
 *
 * @param string $data Plain text to hash
 * @return string Hash of $data
 */
function q_hash($data, $scheme = 'auth') {
    $salt = q_salt($scheme);

    return hash_hmac('md5', $data, $salt);
}

/**
 * Get salt to add to hashes to help prevent attacks.
 *
 * The secret key is located in two places: the database in case the secret key
 * isn't defined in the second place, which is in the config_.php file. If you
 * are going to set the secret key, then you must do so in the config_.php
 * file.
 *
 * The secret key in the database is randomly generated and will be appended to
 * the secret key that is in config_.php file in some instances. It is
 * important to have the secret key defined or changed in config_.php.
 *
 * If you have installed WordPress 2.5 or later, then you will have the
 * SECRET_KEY defined in the config_.php already. You will want to change the
 * value in it because hackers will know what it is. If you have upgraded to
 * WordPress 2.5 or later version from a version before WordPress 2.5, then you
 * should add the constant to your config_.php file.
 *
 * Below is an example of how the SECRET_KEY constant is defined with a value.
 * You must not copy the below example and paste into your config_.php. If you
 * need an example, then you can have a
 * {@link https://api.wordpress.org/secret-key/1.1/ secret key created} for you.
 *
 * <code>
 * define('SECRET_KEY', 'mAry1HadA15|\/|b17w55w1t3asSn09w');
 * </code>
 *
 * Salting passwords helps against tools which has stored hashed values of
 * common dictionary strings. The added values makes it harder to crack if given
 * salt string is not weak.
 *
 * @since 2.5
 * @link https://api.wordpress.org/secret-key/1.1/ Create a Secret Key for config_.php
 *
 * @param string $scheme Authentication scheme
 * @return string Salt value
 */
function q_salt($scheme = 'auth') {
    $secret_key = '';
    if (defined('SECRET_KEY') && ('' != SECRET_KEY))
        $secret_key = SECRET_KEY;

    if ('auth' == $scheme) {
        if (defined('AUTH_KEY') && ('' != AUTH_KEY))
            $secret_key = AUTH_KEY;

        if (defined('AUTH_SALT') && ('' != AUTH_SALT)) {
            $salt = AUTH_SALT;
        } elseif (defined('SECRET_SALT') && ('' != SECRET_SALT)) {
            $salt = SECRET_SALT;
        }
    } elseif ('logged_in' == $scheme) {
        if (defined('LOGGED_IN_KEY') && ('' != LOGGED_IN_KEY))
            $secret_key = LOGGED_IN_KEY;

        if (defined('LOGGED_IN_SALT') && ('' != LOGGED_IN_SALT)) {
            $salt = LOGGED_IN_SALT;
        }
    } elseif ('nonce' == $scheme) {
        if (defined('NONCE_KEY') && ('' != NONCE_KEY))
            $secret_key = NONCE_KEY;

        if (defined('NONCE_SALT') && ('' != NONCE_SALT)) {
            $salt = NONCE_SALT;
        }
    } else {
        // ensure each auth scheme has its own unique salt
        $salt = hash_hmac('md5', $scheme, $secret_key);
    }

    return $salt;
}

?>