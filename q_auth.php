<?php
/* !
 * Version: 1.5
 * Started: 29-04-2010
 * Updated: 05-01-2015
 * Author: giannis [at] paramana dot com
 *
 * Interface for authorization.
 * 
 */

/*
 * include files
 * 
 */
require_once(__DIR__ . "/../../common/init.php");
require_once(ENGINE_PATH . "/init_app.php");

class Q_Auth extends Q_Session {

    /**
     * Singleton object
     *
     * @var Q_Auth
     */
    protected static $instance;

    /**
     * The session class
     * 
     */
//    private $Session;

    /**
     * User IP
     * @var string
     */
    private $client_ip;

    /**
     * the level of blocking
     * @var int
     */
    private $block_attempts = 6;

    /**
     * the level of captcha
     * @var int
     */
    private $captcha_attempts = 3;

    /**
     * Block lifetime this is 60 * 10 means 10 min
     * @var int
     */
    private $block_lifetime = 600;

    /**
     * If remember add this to the expiration time
     * 60*60*24*10 = 864000 which is in 10days
     * 
     * @var int
     */
    private $remember_time = 864000;
    
    /**
     * The expire time in milliseconds
     *
     * @var int
     */
    private $expire_time = 0;

    /**
     * If set to true only one login at a time is allowed
     *
     * @var boolean
     */
    private $single_session = false;

    /**
     * If set to true we display a captcha after the user exceeds
     * captcha failed attempts
     *
     * @var boolean
     */
    private $has_captcha = true;

    /**
     * If set to true the unremember sessions 
     * will expire after the default session time has exceed
     * 
     * @var boolean
     */
    private $expire_sessions = true;

    /**
     * The time that a session without remember will expires
     * this is 60 * 60 * 2 means 2 hours
     * 
     * @var int
     */
    private $default_expire_time = 7200;

    /**
     * Behaves as a contructor
     * And overwrites the init of the Q_Core class 
     */
    protected function init() {
        //get the user"s ip address
        $this->client_ip = myip2long(client_ip());

        $sid = $this->_has_session();
        if ($sid) {
            $this->_get_login_data($sid);
        } 
        else {
            $this->_clean_db_sessions();
            $this->_destoy_session();
        }

        if (defined("SINGLE_SESSION"))
            $this->single_session = SINGLE_SESSION;

        if (defined("EXPIRE_SESSIONS"))
            $this->expire_sessions = EXPIRE_SESSIONS;

        if (defined("SESSION_EXPIRE_TIME"))
            $this->default_expire_time = SESSION_EXPIRE_TIME;

        if (defined("REMEMBER_TIME"))
            $this->remember_time = REMEMBER_TIME;

        if (defined("HAS_CAPTCHA"))
            $this->has_captcha = HAS_CAPTCHA;  

        if (defined("CAPTCHA_ATTEMPTS"))
            $this->captcha_attempts = CAPTCHA_ATTEMPTS;  

        if (defined("BLOCK_ATTEMPTS"))
            $this->block_attempts = BLOCK_ATTEMPTS;    

        if (defined("BLOCK_LIFETIME"))
            $this->block_lifetime = BLOCK_LIFETIME;            
    }
    
    public function get_block_attempts_limit(){
        return $this->block_attempts;
    }

    public function get_block_timer(){
        return $this->block_lifetime;
    }

    /**
     * Returns how many active sessions exist with the current account
     * 
     * @return {int} the current sessions
     */
    public function get_active_sessions_ip(){
        global $idb;

        $query = $idb->prepare("SELECT ip
                                FROM " . DB_PREFIX . "authentication
                                WHERE 
                                    user_id = %d", $this->get_user_id());

        return $idb->get_col($query);
    }
    
    /**
     * Checks if the user level action is allowed
     *
     * @param {int} $user_level the user level to check against
     * @param {boolean} $specific_role if is set to true we need to have excacly the role that we are checking. Default to FALSE
     * @return boolean
     */
    public function is_user_allowed($user_level, $specific_role = FALSE) {
        if ($specific_role)
            return $this->get_role() == $user_level;

        return $this->get_role() >= $user_level;
    }

    /**
     * Check if a user is logged in with Q_Auth.
     * 
     * @return boolean
     * 
     */
    public function is_logged_in() {
        return $this->_get_session() ? true : false;
    }

    static public function authorization($req_type="login"){
        $that = static::$instance;

        $req_type  = sanitze_request($req_type);
        $username  = !empty($_POST["username"]) ? sanitize_user($_POST["username"]) : NULL;
        $password  = !empty($_POST["password"]) ? sanitze_request($_POST["password"]) : NULL;
        $hash_code = !empty($_POST["hash_code"]) ? sanitze_request($_POST["hash_code"]) : NULL;
        $ishuman   = !empty($_POST["ishuman"]) ? sanitze_request($_POST["ishuman"]) : NULL;
        $ismobile  = !empty($_POST["ismobile"]) ? sanitze_request($_POST["ismobile"]) : NULL;
        $requested = !empty($_POST["requested"]) ? explode("#", sanitze_request($_POST["requested"]), 2) : NULL;

        if ($ishuman != "yep")
            return response_message("UNAUTHORIZED", "refresh2");
        if (!$username)
            return response_message("UNAUTHORIZED", "error_username");
        if (!$password && $req_type != 'recover-pass')
            return response_message("UNAUTHORIZED", "error_password");
        
        if (!$ismobile) {
            if (!$requested || count($requested) != 2)
                return response_message("UNAUTHORIZED", "refresh");

            list($when, $hash) = $requested;
            if ($hash !== sha1(LOGGED_IN_SALT . $when . LOGGED_IN_SALT) || $when < (time() - 30 * 60)) {
                // error condition, redisplay form; either
                // corrupted or the form was served > 30 minutes
                // ago
                return response_message("UNAUTHORIZED", "refresh");
            }
        }

        $blockLevel = $that->is_blocked();

        if ($blockLevel == "BLOCK")
            return response_message("UNAUTHORIZED", "error_block");

        if ($blockLevel == "CAPTCHA") {
            if (empty($_POST["captcha"]))
                return response_message("UNAUTHORIZED", "error_captcha");

            require_once(APP_ROOT . "/common/classes/securimage/securimage.php");
            $SecureImg = new Securimage();

            if ($SecureImg->getCode() != strtolower(sanitize_user($_POST["captcha"]))) {
                $that->_set_block();
                return response_message("UNAUTHORIZED", "wrong_captcha");
            }
        }

        if ($req_type == "signup")
            return $that->signup($username, $password);

        if ($req_type == "recover-pass")
            return $that->recover_password($username);

        if ($req_type == "reset-pass")
            return $that->reset_password($username, $password, $hash_code);

        return $that->login($username, $password, $ismobile);
    }

    private function reset_password($username, $password, $reset_hash){
        if (!$reset_hash)
            return response_message("INVALID_REQUEST", "error_activate");

        global $idb;

        $query = $idb->prepare("SELECT user_id, user_status, user_activation_key
                                FROM " . DB_PREFIX . "users
                                WHERE user_name = %s AND user_activation_key = %s", $username, $reset_hash);

        $db_result = $idb->get_row($query);

        if (!$db_result)
            return response_message("NO_USENAME", "error_no_user");

        if ($db_result->user_status != 'reset-pass')
            return response_message("INVALID_REQUEST", "error_general");

        if ($db_result->user_activation_key != $reset_hash)
            return response_message("INVALID_REQUEST", "error_general");

        $idb->update(DB_PREFIX . "users", 
                                    array(
                                        "user_pass"=>$password,
                                        "user_status"=>"active", 
                                        "user_activation_key"=>""
                                    ), 
                                    array("user_id"=>$db_result->user_id),
                                    array("%s", "%s", "%s"),
                                    array("%d")
                                );

        $this->authentication($username, $password);

        return response_message("SUCCESS", user_login_path($this->get_role()));
    }

    private function recover_password($username){
        global $idb;

        $query = $idb->prepare("SELECT u.user_id, u.user_role, u.user_status, u.user_activation_key,
                                       um.first_name, um.last_name, um.email, um.phone
                                FROM " . DB_PREFIX . "users u
                                INNER JOIN " . DB_PREFIX . "user_meta um ON (u.user_id = um.user_id)
                                WHERE user_name = %s", $username);

        $db_result = $idb->get_row($query);

        if (!$db_result)
            return response_message("NO_USENAME", "error_username");

        if ($db_result->user_status == 'activation')
            return response_message("ACTIVATION_NEEDED", "error_activation_needed");

        $reset_password_hash = q_hash($username . time(), "logged_in");
        $idb->update(DB_PREFIX . "users", 
                                    array(
                                        "user_status"=>"reset-pass", 
                                        "user_activation_key"=>$reset_password_hash
                                    ), 
                                    array("user_id"=>$db_result->user_id),
                                    array("%s", "%s"),
                                    array("%d")
                                );

        $Email_App = Email::i();

        return $Email_App->send(
                        "password-recovery", 
                        array(
                            "reset_password_hash"=>$reset_password_hash,
                            "email_to"=>$username,
                            "first_name"=>$db_result->first_name,
                            "last_name"=>$db_result->last_name
                        ));
    }

    private function signup($username, $password){
        if (!filter_var($username, FILTER_VALIDATE_EMAIL))
            return response_message("ACTIVATION_FAILED", "error_username");

        $first_name   = !empty($_POST["first_name"]) ? strip_all_tags($_POST["first_name"]) : NULL;
        $last_name    = !empty($_POST["last_name"]) ? strip_all_tags($_POST["last_name"]) : NULL;
        $redirect_url = "";

        if (!$first_name)
            return response_message("ACTIVATION_FAILED", "error_first_name");
        if (!$last_name)
            return response_message("ACTIVATION_FAILED", "error_last_name");

        $user_data = $this->_get_user("username", $username);
        
        if ($user_data)
            return response_message("ACTIVATION_FAILED", "error_user_exists");

        $activation_hash = q_hash($username . time(), "logged_in");

        global $idb; //the db class
        
        $idb->insert(DB_PREFIX . "users",
                        array(
                            "user_name"=>$username,
                            "user_pass"=>$password,
                            "user_role"=>1,
                            "user_expire_date"=>"",
                            "user_status"=>"activation",
                            "user_activation_key"=>$activation_hash
                        ), 
                        array(
                            "%s", "%s", "%d", "%s", "%s", "%s"
                        ));
        
        $user_id = $idb->insert_id;

        $idb->insert(DB_PREFIX . "user_meta",
                    array(
                        "user_id"=>$user_id,
                        "first_name"=>$first_name,
                        "last_name"=>$last_name,
                        "email"=>$username
                    ), 
                    array(
                        "%d", "%s", "%s", "%s"
                    ));

        $idb->insert(DB_PREFIX . "user_options", 
                    array(
                        "user_id"=>$user_id,
                        "option_key"=>"talent_visibility",
                        "option_value"=>1
                    ), 
                    array("%d", "%s", "%d")
                );

        if ($idb->last_error)
            return array($idb->last_error);
        
        if (!empty($errors))
            return $errors;

        //login the user
        $this->authentication($username, $password);

        $Activation = Q_Activation::i();

        if (!empty($Activation))
            return $Activation->send_activation($username, $activation_hash, $first_name, $last_name);

        return true;
    }

    private function login($username, $password, $ismobile=FALSE) {
        if (!empty($_POST["remember"])) {
            if (is_numeric($_POST["remember"]))
                $this->expire_time = time() + $_POST["remember"];
            else
                $this->expire_time = time() + $this->remember_time;
        }
        else {
            $this->expire_time = time() + $this->default_expire_time;
        }

        if (!$this->authentication($username, $password)) {
            $blockLevel = $this->is_blocked();

            if ($blockLevel == "BLOCK")
                return response_message("UNAUTHORIZED", "error_block");
            else
                return response_message("UNAUTHORIZED", "error_username");
        }

        if ($this->user_data->user_status == 'reset-pass')
            $this->_update_user_status('active');

        if ($ismobile)
            return response_message("SUCCESS", $this->_get_session());

        return response_message("SUCCESS", user_login_path($this->get_role()));
    }

    /**
     * Authenticate user with remember capability.
     *
     * The various authentication cookies will be set by this function and will be
     * set for a longer period depending on if the "remember" credential is set to
     * true.
     *
     * @param string $username
     * @param string $password
     * @return boolean
     * 
     */
    private function authentication($username, $password) {
        if (empty($username) || empty($password))
            return false;

        global $idb;

        $user_data = $this->_get_user("username", $username);

        if (!$user_data || !$this->_check_password($password, $user_data->user_pass, $user_data->user_id)) {
            $this->_set_block();
            return false;
        }

        if (!empty($user_data->user_expire_date) && $user_data->user_expire_date != "0000-00-00" && strtotime($user_data->user_expire_date) < time())
            return response_message("UNAUTHORIZED", "error_user_expired");

        $session_ids = $this->_create_new_session($user_data);

        if ($this->_has_auth_data())
            return true;

        if (!empty($this->expire_time))
            $user_data->{"expire"} = $this->expire_time;

        $this->_clean_db_sessions();

        $this->client_ip = myip2long(client_ip());

        $this->_set_last_login_date();
        $this->_remove_block();

        $idb->insert(DB_PREFIX . "authentication", array(
            "session_id" => $session_ids[0],
            "session_id_" => $session_ids[1],
            "ip" => $this->client_ip,
            "user_role" => $this->get_role(),
            "expire" => date("Y-m-d H:i:s", $this->expire_time),
            "user_id" => $this->get_user_id())
        );

        $this->user_status = $user_data->user_status;

        return true;
    }

    /**
     * Destroy session
     * 
     */
    static public function logout() {
        $that    = static::$instance;
        $request = !empty($_REQUEST) ? sanitze_request($_REQUEST) : array();
        
        global $idb;
        
        $idb->delete(DB_PREFIX . "authentication", array("session_id" => $that->_get_session(true)), array("%s"));

        $that->_destoy_session();

        if (!empty($request["simple"]))
            return;

        if (isset($request["redirect"]))
            header("Location: " . $request["redirect"]);
        else
            header("Location: " . BASE_PATH . "signin/");
    }

    /**
     * Check if user is blocked
     *
     * @return string - based on level of block, false if not
     */
    public function is_blocked() {
        global $idb;

        $block_action = NULL;
        $when_blocked = NULL;

        $query = $idb->prepare("SELECT block_action, when_blocked 
                                FROM " . DB_PREFIX . "block_list 
                                WHERE ip = %d LIMIT 1", $this->client_ip);

        if ($block_state = $idb->get_row($query)) {
            $block_action = $block_state->block_action;
            $when_blocked = $block_state->when_blocked;

            //expires the block if the block time has exceed its lifetime
            if ($block_action == "BLOCK" && strtotime($when_blocked) + $this->block_lifetime < time()) {
                $this->_remove_block();
                return false;
            }

            return $block_action;
        }
        return false;
    }

    /**
     * Creates a sha to use from a salt and time
     * 
     * @return string the sha1 string
     */
    public function get_signed_sha() {
        $now = time();
        return $now . "#" . sha1(LOGGED_IN_SALT . $now . LOGGED_IN_SALT);
    }

    /**
     * Checks if the user has session data in the authentication table
     * 
     * @return boolean
     * 
     */
    private function _has_auth_data() {
        global $idb;

        $session_data = $this->_get_session();

        if (!$session_data)
            return false;

        $query = $idb->prepare("SELECT user_id 
                                FROM " . DB_PREFIX . "authentication 
                                WHERE 
                                    session_id = %s 
                                 AND 
                                    session_id_ = %s", $session_data[0], $session_data[1]);

        return $idb->get_var($query);
    }

    /**
     * Gets the login information from the db
     *
     * @return boolean
     * 
     */
    private function _get_login_data($session_ids) {
        global $idb;

        if (empty($idb) || count($session_ids) != 2)
            return false;

        $query = $idb->prepare("SELECT session_id, session_id_, ip, user_role, user_id, expire
                                FROM " . DB_PREFIX . "authentication
                                WHERE 
                                    session_id = %s
                                AND
                                    session_id_ = %s", $session_ids[0], $session_ids[1]);

        if ($login_data = $idb->get_row($query)) {
            $this->_update_session($login_data);
            return true;
        } 
        else {
            $this->_destoy_session();
        }

        return false;
    }

    /**
     * Sets the last login date to the db
     * 
     * @return object
     * 
     */
    private function _set_last_login_date() {
        global $idb;

        $idb->update(DB_PREFIX . "users", array("user_last_login" => date("Y-m-d H:i:s")), array("user_id" => $this->get_user_id()));
    }

    /**
     * 
     * Sets the block level
     * 
     * 
     */
    private function _set_block() {
        if ($this->debug)
            return true;

        global $idb;

        $block_action = NULL;
        $attempts     = NULL;
        $when_blocked = NULL;

        $query = $idb->prepare("SELECT block_action, attempts, when_blocked
                                FROM " . DB_PREFIX . "block_list
                                WHERE ip = %s", $this->client_ip);

        if ($block_state = $idb->get_row($query)) {
            $block_action = $block_state->block_action;
            $when_blocked = $block_state->when_blocked;
            $attempts = $block_state->attempts + 1;
        } 
        else {
            $attempts = 1;
        }

        if ($attempts > $this->block_attempts)
            $block_action = "BLOCK";
        else if ($this->has_captcha && $attempts > $this->captcha_attempts)
            $block_action = "CAPTCHA";
        else
            $block_action = "";

        $idb->replace(DB_PREFIX . "block_list", array("ip" => $this->client_ip, "attempts" => $attempts, "block_action" => $block_action));
    }

    /**
     *
     * Removes the block level
     * 
     */
    private function _remove_block() {
        global $idb;
        $idb->delete(DB_PREFIX . "block_list", array("ip" => $this->client_ip), array("%d"));
    }

    /**
     * Clean db from old sessions
     * 
     */
    private function _clean_db_sessions() {
        global $idb;
        
        if ($this->single_session) {
            $this->_keep_single_sessions();
        }

        $user_id = $this->get_user_id();
        $query = $idb->prepare("DELETE FROM " . DB_PREFIX . "authentication 
                                   WHERE (user_id = %d) AND expire <= NOW()", $user_id);

        $idb->query($query);
    }

    /**
     * Checks the plaintext password against the encrypted Password.
     *
     * Maintains compatibility between old version and the new cookie authentication
     * protocol using PHPass library. The $hash parameter is the encrypted password
     * and the function compares the plain text password when encypted similarly
     * against the already encrypted password to see if they match.
     *
     * For integration with other applications, this function can be overwritten to
     * instead use the other package password checking algorithm.
     *
     * @since 2.5
     * @global object $q_hasher PHPass object used for checking the password
     * 	against the $hash + $password
     * @uses PasswordHash::CheckPassword
     *
     * @param string $password Plaintext user"s password already md5 from the client
     * @param string $hash Hash of the user"s password to check against.
     * @return bool False, if the $password does not match the hashed password
     */
    private function _check_password($password, $hash, $user_id = "") {
        global $q_hasher;

        // If the hash is still md5...
        if (strlen($hash) <= 32) {
            $check = ( $hash == md5($password) ) || ($hash == $password);
            if ($check && ($user_id || $user_id == 0)) {
                // Rehash using new hash.
                $hash = q_hash_password($password);

                $this->_update_password($hash, $user_id);
            }

            return $check;
        }

        // If the stored hash is longer than an MD5, presume the
        // new style phpass portable hash.
        if (empty($q_hasher)) {
            require_once( APP_ROOT . "/common/classes/phpass.class.php");
            // By default, use the portable hash from phpass
            $q_hasher = new PasswordHash(8, FALSE);
        }

        $check = $q_hasher->CheckPassword($password, $hash);

        return $check;
    }

    /**
     * Updates the user"s password with a new encrypted one.
     *
     * For integration with other applications, this function can be overwritten to
     * instead use the other package password checking algorithm.
     *
     * @since 2.5
     * @uses $idb database object for queries
     *
     * @param string $password The plaintext new user password
     * @param int $user_id User ID
     */
    private function _update_password($hash, $user_id) {
        global $idb;

        $idb->update(DB_PREFIX . "users", array("user_pass" => $hash), array("user_id" => $user_id));
    }

    /**
     * Retrieve user info by a given field
     *
     * @since 2.8.0
     *
     * @param string $field The field to retrieve the user with.  id | slug | email | login
     * @param int|string $value A value for $field.  A user ID, slug, email address, or login name.
     * @return bool|object False on failure, User DB row object
     */
    private function _get_user($field, $value) {
        global $idb;

        switch ($field) {
            case "user_id":
                $field = "user_id";
                break;
            case "username":
                $value = sanitize_user($value);
                $field = "user_name";
                break;
            default:
                return false;
        }

        if (!$user = $idb->get_row($idb->prepare("SELECT * FROM " . DB_PREFIX . "users WHERE $field = %s", $value)))
            return false;

        return $this->user_data = $user;
    }

    private function _update_user_status($user_status="active"){
        global $idb;

        $idb->update(DB_PREFIX . "users", 
                                        array("user_status"=>$user_status, "user_activation_key"=>""), 
                                        array("user_id"=>$this->get_user_id()),
                                        array("%s", "%s"),
                                        array("%d")
                                    );
    }
}
?>