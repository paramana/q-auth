<?php
/* !
 * Version: 1.0
 * Updated: 15-02-2014
 * Updated: 15-02-2014
 *
 * Copyright (c) 2014 paramana.com
 * 
 */

/**
 * Navigates through an array and removes slashes from the values.
 *
 * If an array is passed, the array_map() function causes a callback to pass the
 * value back to the function. The slashes from this value will removed.
 *
 * @since 2.0.0
 *
 * @param array|string $value The array or string to be stripped.
 * @return array|string Stripped array (or string in the callback).
 */
if(!function_exists("stripslashes_deep")) {
    function stripslashes_deep($value) {
        if ( is_array($value) ) {
            $value = array_map('stripslashes_deep', $value);
        } elseif ( is_object($value) ) {
            $vars = get_object_vars( $value );
            foreach ($vars as $key=>$data) {
                $value->{$key} = stripslashes_deep( $data );
            }
        } else {
            $value = stripslashes($value);
        }

        return $value;
    }
}

/**
 * Properly strip all HTML tags including script and style
 *
 * @since 2.9.0
 *
 * @param string $string String containing HTML tags
 * @param bool $remove_breaks optional Whether to remove left over line breaks and white space chars
 * @return string The processed string.
 */
if(!function_exists("strip_all_tags")) {
    function strip_all_tags($string, $remove_breaks = false) {
        $string = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $string );
        $string = strip_tags($string);

        if ( $remove_breaks )
            $string = preg_replace('/[\r\n\t ]+/', ' ', $string);

        return trim($string);
    }
}

/**
 * Sanitize username stripping out unsafe characters.
 *
 * Removes tags, octets, entities, and if strict is enabled, will only keep
 * alphanumeric, _, space, ., -, @. After sanitizing, it passes the username,
 * raw username (the username in the parameter), and the value of $strict as
 * parameters for the 'sanitize_user' filter.
 *
 * @since 2.0.0
 * @uses apply_filters() Calls 'sanitize_user' hook on username, raw username,
 *      and $strict parameter.
 *
 * @param string $username The username to be sanitized.
 * @param bool $strict If set limits $username to specific characters. Default false.
 * @return string The sanitized username, after passing through filters.
 */
if(!function_exists("sanitize_user")) {
    function sanitize_user( $username, $strict = false ) {
        $raw_username = $username;
        $username = strip_all_tags( $username );
        $username = remove_accents( $username );
        // Kill octets
        $username = preg_replace( '|%([a-fA-F0-9][a-fA-F0-9])|', '', $username );
        $username = preg_replace( '/&.+?;/', '', $username ); // Kill entities

        // If strict, reduce to ASCII for max portability.
        if ( $strict )
            $username = preg_replace( '|[^a-z0-9 _.\-@]|i', '', $username );

        $username = trim( $username );
        // Consolidate contiguous whitespace
        $username = preg_replace( '|\s+|', ' ', $username );

        return $username;
    }
}

function sanitze_request($request){
    if ( !is_array($request) ) {
        return stripslashes(strip_all_tags($request));
    }

    foreach ($request as &$value) {
        $value = stripslashes(strip_all_tags($value));
    }

    return $request;
}
?>