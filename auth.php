<?php
/**
 * DokuWiki Plugin duneauth (Auth Component)
 *
 * Requires php7.4-sqlite be installed.
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Paradox <daniel@binaryparadox.net>
 */

// NB: This must match the value of HASH_METHOD from authd.h in-lib.
define("AUTHD_HASH_METHOD_BCRYPT", 0x01);

// must be run within Dokuwiki
if (!defined('DOKU_INC')) {
  die();
}

// duneauth_db is a class that abstracts away the choice of database and the raw
// queries from the auth plugin.
class duneauth_db extends SQLite3 {

  public function __construct($dbfile) {
    $this->open($dbfile, SQLITE3_OPEN_READONLY, "");
  }

  // getBcryptHash fetches the hash digest for a given user and enforces that
  // it's a bcrypt hash that hasn't expired. Temporary passwords are ignored.
  public function getBcryptHash($user) {
    // NB: We deliberately don't consider temporary passwords in this query.
    // Those should only be used to log into the game to change the real AUTHD
    // password for a character.
    $stmt = $this->prepare("SELECT ".
             "  p.digest, p.method, p.expires_at ".
             "FROM characters c ".
             "  INNER JOIN passwords p ".
             "    ON c.password = p.id ".
             "WHERE c.name = :name AND flags <> 0 ".
             "LIMIT 1");
    $stmt->bindValue(":name", $user, SQLITE3_TEXT);

    $res = $stmt->execute();
    if(!$res) {
      // query failure.
      return False;
    }
    $row = $res->fetchArray(SQLITE3_ASSOC);

    if(count($row) != 3) {
      // bad result.
      return False;
    }

    $digest = $row['digest'];
    $method = $row['method'];
    $expires_at = $row['expires_at'];

    if($method != AUTHD_HASH_METHOD_BCRYPT) {
      // unknown hash method.
      return False;
    }

    $now = new DateTime();
    $nowTS = $now->getTimestamp();
    if($expiry != 0 && $expiry < $nowTS) {
      // password was expired.
      return False;
    }

    return $digest;
  }

  // getUserData returns user data for the given user.
  public function getUserData($user) {
    $stmt = $this->prepare("SELECT ".
             "  email, admin, immortal ".
             "FROM characters ".
             "WHERE name = :name AND flags <> 0");
    $stmt->bindValue(":name", $user, SQLITE3_TEXT);

    $res = $stmt->execute();
    if(!$res) {
      // query failure.
      return False;
    }
    $row = $res->fetchArray(SQLITE3_ASSOC);

    $groups = array('user');
    if($row['admin'] == 1) {
      array_push($groups, 'admin');
    }
    if($row['immortal'] == 1) {
      array_push($groups, 'immortal');
    }

    return array(
      'name' => $user,
      'mail' => $row['email'],
      'grps' => $groups);
  }

  // getUserCount returns a count of registered users.
  public function getUserCount($filter) {
    // TODO: Consider $filter - not clear where the UI exposes filtering so for
    // now ignoring.
    $stmt = $this->prepare("SELECT ".
             "  COUNT(id) AS userCount ".
             "FROM characters ".
             "WHERE flags <> 0");
    $res = $stmt->execute();
    if(!$res) {
      // query failure.
      return False;
    }
    $row = $res->fetchArray(SQLITE3_ASSOC);
    return $row['userCount'];
  }

  // getUsers returns user information with support for cursoring.
  public function getUsers($start = 0, $limit = 0, $filter = array()) {
    // TODO: Consider $filter - not clear where the UI exposes filtering so for
    // now ignoring.
    $query = "SELECT ".
             " name, email, admin, immortal ".
             "FROM characters ".
             "WHERE flags <> 0 ".
             "LIMIT :limit ".
             "OFFSET :offset";
    $stmt = $this->prepare($query);
    $stmt->bindValue(":offset", $start, SQLITE3_INTEGER);
    $stmt->bindValue(":limit", $limit, SQLITE3_INTEGER);

    $res = $stmt->execute();
    if(!$res) {
      // query failure.
      return array();
    }

    $out = array();

    while($row = $res->fetchArray(SQLITE3_ASSOC)) {
      $groups = array('user');
      if($row['admin'] == 1) {
        array_push($groups, 'admin');
      }
      if($row['immortal'] == 1) {
        array_push($groups, 'immortal');
      }

      $out[$row['name']] = array(
        'name' => $row['name'],
        'mail' => $row['email'],
        'grps' => $groups,
      );
    }

    return $out;
  }
}

// auth_plugin_duneauth implements DokuWiki authentication with the DuneLib
// AUTHD database.
class auth_plugin_duneauth extends DokuWiki_Auth_Plugin {

  public function __construct() {
    parent::__construct();

    // The AUTHD login plugin can do very few things - we want players to edit
    // their information in-game, not with the wiki.
    $this->cando['getUsers']     = true;  // can a (filtered) list of users be retrieved?
    $this->cando['getUserCount'] = true;  // can the number of users be retrieved?
    $this->cando['logout']       = true;  // can the user logout again? (eg. not possible with HTTP auth)

    // Everything else is disabled when this plugin is in charge of auth.
    $this->cando['addUser']      = false; // can Users be created?
    $this->cando['delUser']      = false; // can Users be deleted?
    $this->cando['modLogin']     = false; // can login names be changed?
    $this->cando['modPass']      = false; // can passwords be changed?
    $this->cando['modName']      = false; // can real names be changed?
    $this->cando['modMail']      = false; // can emails be changed?
    $this->cando['modGroups']    = false; // can groups be changed?
    $this->cando['getGroups']    = false; // can a list of available groups be retrieved?
    $this->cando['external']     = false; // does the module do external auth checking?

    // Load the SQLite DB file location from configuration.
    $this->loadConfig();
    $dbfile = $this->getConf("db");
    if(!$dbfile) {
      //$this->debugMsg('No db file specified', -1, __LINE__);
      $this->success = false;
      return;
    }

    $this->db = new duneauth_db($dbfile);
    $this->success = true;
  }

  /**
   * Check user+password
   *
   * @param   string $user the user name
   * @param   string $pass the clear text password
   *
   * @return  bool
   */
  public function checkPass($user, $pass) {
    $hash = $this->db->getBcryptHash($user);

    // PHP's password_hash/password_verify expect bcrypt hashes to have a prefix
    // '$2y$' but the Python impl we use generates '$2b$'. We fix that here.
    $my_hash2 = preg_replace ('/^\$2b\$/', '\$2y\$', $hash, 1);

    return password_verify($pass, $my_hash2);
  }

  /**
   * Return user info
   *
   * Returns info about the given user needs to contain
   * at least these fields:
   *
   * name string  full name of the user
   * mail string  email addres of the user
   * grps array   list of groups the user is in
   *
   * @param   string $user          the user name
   * @param   bool   $requireGroups whether or not the returned data must include groups
   *
   * @return  array  containing user data or false
   */
  public function getUserData($user, $requireGroups=true) {
    return $this->db->getUserData($user);
  }

  /**
   * Return a count of the number of user which meet $filter criteria
   *
   * @param array $filter
   * @return int
   */
  public function getUserCount($filter = array())
  {
    return $this->db->getUserCount($filter);
  }

  /**
   * Bulk retrieval of user data
   *
   * @param   int   $start index of first user to be returned
   * @param   int   $limit max number of users to be returned
   * @param   array $filter array of field/pattern pairs
   * @return  array userinfo (refer getUserData for internal userinfo details)
   */
  public function retrieveUsers($start = 0, $limit = 0, $filter = array()) {
    return $this->db->getUsers($start, $limit, $filter);
  }

  /**
   * Return case sensitivity of the backend
   *
   * @return bool
   */
  public function isCaseSensitive() {
    return true; // always true for AUTHD
  }

  /**
   * Sanitize a given username
   *
   * This function is applied to any user name that is given to
   * the backend and should also be applied to any user name within
   * the backend before returning it somewhere.
   *
   * This should be used to enforce username restrictions.
   *
   * @param string $user username
   * @return string the cleaned username
   */
  public function cleanUser($user) {
    // NOP - we use prepared statements and don't need to do any extra
    // sanitization. We also do not allow new registrations via the wiki to enforce
    // username restrictions here.
    return $user;
  }

  /**
   * Sanitize a given groupname
   *
   * This function is applied to any groupname that is given to
   * the backend and should also be applied to any groupname within
   * the backend before returning it somewhere.
   *
   * This should be used to enforce groupname restrictions.
   *
   * Groupnames are to be passed without a leading '@' here.
   *
   * @param  string $group groupname
   *
   * @return string the cleaned groupname
   */
  public function cleanGroup($group) {
    // NOP - we use prepared statements and don't need to do any extra
    // sanitization. 
    return $group;
  }
}
