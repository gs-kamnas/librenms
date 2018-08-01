<?php

namespace LibreNMS\Authentication;

use LibreNMS\Config;
use LibreNMS\Exceptions\AuthenticationException;

class ADAuthorizationAuthorizer extends ActiveDirectoryAuthorizer
{
    protected static $AUTH_IS_EXTERNAL = 1;
    protected static $CAN_UPDATE_PASSWORDS = 0;

    protected $ldap_connection;

    public function __construct()
    {
        if (! isset($_SESSION['username'])) {
            $_SESSION['username'] = '';
        }
    }

    public function authenticate($username, $password)
    {
        if (isset($_SERVER['REMOTE_USER'])) {
            $_SESSION['username'] = mres($_SERVER['REMOTE_USER']);
            if ($this->userExists($_SESSION['username'])) {
                return true;
            }

            $_SESSION['username'] = Config::get('http_auth_guest');
            return true;
        }

        throw new AuthenticationException();
    }

    public function userExists($username, $throw_exception = false)
    {
        if ($this->authLdapSessionCacheGet('user_exists')) {
            return 1;
        }

        if (parent::userExists($username, $throw_exception)) {
            /*
             * Cache positive result as this will result in more queries which we
             * want to speed up.
             */
            $this->authLdapSessionCacheSet('user_exists', 1);
            return 1;
        }

        return 0;
    }

    public function getUserlevel($username)
    {
        $userlevel = $this->authLdapSessionCacheGet('userlevel');
        if ($userlevel) {
            return $userlevel;
        } else {
            $userlevel = parent::getUserLevel($username);
        }
        $this->authLdapSessionCacheSet('userlevel', $userlevel);
        return $userlevel;
    }

    public function getUserid($username)
    {
        $userid = $this->authLdapSessionCacheGet('userid');
        if ($userid) {
            return $userid;
        } else {
            $userid = parent::getUserid($username);
        }
        $this->authLdapSessionCacheSet('userid', $userid);
        return $userid;
    }

    protected function authLdapSessionCacheGet($attr)
    {
        $ttl = 300;
        if (Config::get('auth_ldap_cache_ttl')) {
            $ttl = Config::get('auth_ldap_cache_ttl');
        }

        // auth_ldap cache present in this session?
        if (! isset($_SESSION['auth_ldap'])) {
            return null;
        }

        $cache = $_SESSION['auth_ldap'];

        // $attr present in cache?
        if (! isset($cache[$attr])) {
            return null;
        }

        // Value still valid?
        if (time() - $cache[$attr]['last_updated'] >= $ttl) {
            return null;
        }
        return $cache[$attr]['value'];
    }


    protected function authLdapSessionCacheSet($attr, $value)
    {
        $_SESSION['auth_ldap'][$attr]['value'] = $value;
        $_SESSION['auth_ldap'][$attr]['last_updated'] = time();
    }
}
