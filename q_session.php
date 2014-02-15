<?php

/* !
 * Version: 1.0
 * Started: 20-11-2012
 * Updated: 15-02-2014
 * Author: giannis [at] paramana dot com
 *
 * The class that handles the session data
 * 
 */

abstract class Q_Session {
    /**
     * Singleton object
     *
     * @var Q_Session
     */

    /**
     * User role
     * @var string
     * 
     * 10-> admin
     * 1-> user
     * 
     */
    private $user_role;

    /**
     * User role name
     * @var string
     * 
     * 
     */
    private $user_role_type;

    /**
     * Session id
     * @var string
     */
    private $session_id;

    /**
     * The second session id
     * @var string
     */
    private $session_id_;

    /**
     * The user id from the users table
     * @var int
     */
    private $user_id;

    /**
     * User IP
     * @var string
     */
    private $client_ip;

    /**
     * Default it expires at the end of the session
     * 
     * @var int
     */
    private $expire = 0;
    private $cookie_prefix = "";
    protected $debug = false;

    /**
     * All constructeur should be protected
     * 
     */
    final private function __construct() {
        // if called twice ....
        if (isset(static::$instance))
        // throws an Exception
            throw new Exception("An instance of " . get_called_class() . " already exists.");

        session_start();

        if (defined("COOKIE_PREFIX") && COOKIE_PREFIX)
            $this->cookie_prefix = COOKIE_PREFIX;

        if (defined("DEBUG") && DEBUG)
            $this->debug = DEBUG;

        // init method via magic static keyword ($this injected)
        static::init();
    }

    /**
     * The init function
     * Can be overidden from the child class
     * 
     */
    protected function init() {
        
    }

    /**
     * PHP5 style destructor.
     *
     * @return bool true
     */
    function __destruct() {
        return true;
    }

    /**
     * no clone allowed, both internally and externally
     */
    final private function __clone() {
        throw new Exception("An instance of " . get_called_class() . " cannot be cloned.");
    }

    /**
     * Singleton method.
     *
     * @return Q_Auth
     */
    final public static function i() {
        return isset(static::$instance) ? static::$instance : static::$instance = new static;
    }

    /**
     * Get the logged in user id
     *
     * @return int
     */
    public function get_user_id() {
        return $this->user_id;
    }

    /**
     * Get the user role
     *
     * @return int
     */
    public function get_role() {
        return $this->user_role;
    }

    /**
     * Get the user role name
     *
     * @return string
     */
    public function get_role_name() {
        return $this->user_role_type;
    }

    /**
     * Check if user is admin
     *
     * @return int
     */
    public function is_user_admin() {
        return $this->user_role_type == "admin";
    }

    public function is_admin_page() {
        return (!empty($_REQUEST["action"]) && $_REQUEST["action"] == "admin") || strrpos($_SERVER["REQUEST_URI"], "admin") !== FALSE ? true : false;
    }

    /**
     * Destorys the session data
     */
    protected function _destoy_session() {
        $this->user_id = null;
        $this->client_ip = null;
        $this->expire = 0;
        $this->session_id = "";
        $this->session_id_ = "";

        $this->_set_user_role();
        $this->_set_cookie(true);
    }

    /**
     * Checks if a session or cookie exists
     *
     * @return string false if we does not exist
     */
    protected function _has_session() {
        //check if a session or cookie exists,
        if (!empty($_SESSION[$this->cookie_prefix . "sid"]) && !empty($_SESSION[$this->cookie_prefix . "sid_"])) {
            $this->session_id = $_SESSION[$this->cookie_prefix . "sid"];
            $this->session_id_ = $_SESSION[$this->cookie_prefix . "sid_"];
            return array($this->session_id, $this->session_id_);
        } else if (!empty($_COOKIE[$this->cookie_prefix . "sid"]) && !empty($_COOKIE[$this->cookie_prefix . "sid_"])) {
            $this->session_id = $_COOKIE[$this->cookie_prefix . "sid"];
            $this->session_id_ = $_COOKIE[$this->cookie_prefix . "sid_"];
            return array($this->session_id, $this->session_id_);
        }

        return false;
    }

    /**
     * Get the session id
     * 
     * $main_one boolean (default to true) if true checks only for the main session
     *
     * @return string|array if $main_one is true then returns a string 
     *                      if false then returns an array if the two sessions
     */
    protected function _get_session($main_one = false) {
        if (empty($this->session_id))
            return false;

        if ($main_one)
            return $this->session_id;

        if (empty($this->session_id_))
            return false;

        return array($this->session_id, $this->session_id_);
    }

    /**
     * Protected function to start a new session
     * 
     * @param object $data
     * 
     */
    protected function _create_new_session($data) {
        $this->_set_session_data($data);
        $this->_set_cookie();
        return $this->_get_session();
    }

    /**
     * Protected function to update the session data
     * 
     * @param object $data
     * 
     */
    protected function _update_session($data) {
        $this->_set_session_data($data);
        return $this->_get_session();
    }

    protected function _keep_single_sessions(){
        global $idb;

        $user_id = $this->get_user_id();

        $idb->delete(DB_PREFIX . "authentication", array("user_id"=>$user_id), array("%d"));
    }

    /**
     * Sets the login information from an object
     * and creates a user object
     * 
     * @param object $data
     * 
     */
    private function _set_session_data($data) {
        $this->_set_user_role(is_numeric($data->user_role) ? $data->user_role : 1);

        $this->user_id = !empty($data->user_id) ? $data->user_id : $data->user_id;
        $this->session_id = !empty($data->session_id) ? $data->session_id : $this->_make_session_id($data->user_id, $this->expire);
        $this->session_id_ = !empty($data->session_id_) ? $data->session_id_ : $this->_make_session_id($data->user_id, $this->expire, "other");
        $this->client_ip = !empty($data->ip) ? $data->ip : sprintf(ip2long(client_ip()));
        $this->expire = (!empty($data->expire) && $data->expire != "0000-00-00 00:00:00") ? $data->expire : 0;
    }

    /**
     * Set cookies
     * 
     * @param boolean $destroy if true destroy the session
     * 
     */
    private function _set_cookie($destroy = false) {
        setcookie($this->cookie_prefix . "sid", $this->session_id, $this->expire, BASE_PATH, "", false, true);
        setcookie($this->cookie_prefix . "sid_", $this->session_id_, $this->expire, BASE_PATH, "", false, true);
        if (!$destroy) {
            $_SESSION[$this->cookie_prefix . "sid"] = $this->session_id;
            $_SESSION[$this->cookie_prefix . "sid_"] = $this->session_id_;
        } else {
            if (isset($_SESSION[$this->cookie_prefix . "sid"])) {
                session_destroy();
                session_unset();
            }
        }
    }

    /**
     * Generate authentication cookie contents.
     *
     * @since 2.5
     *
     * @param int $user User ID
     * @param int $expiration Cookie expiration in seconds
     * @param string $scheme Optional. The cookie scheme to use: auth, or logged_in
     * @return string Authentication cookie contents
     */
    private static function _make_session_id($user, $expiration, $scheme = "auth") {
        $key = q_hash($user . "|" . $expiration . '|' . time(), $scheme);
        $hash = hash_hmac("sha256", $user . "|" . $expiration, $key);

        return $hash . ":" . time();
    }

    private function _set_user_role($role = NULL) {
        if (empty($role)) {
            $this->user_role = null;
            return;
        }

        $user_level_name = user_level_name($role);

        $this->user_role = $role;
        $this->user_role_type = $user_level_name[1];
        $this->user_role_name = $user_level_name[2];
    }

}

?>