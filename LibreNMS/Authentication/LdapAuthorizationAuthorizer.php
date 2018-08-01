<?php
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * libreNMS HTTP-Authentication and LDAP Authorization Library
 *
 * @author     Maximilian Wilhelm <max@rfc2324.org>
 * @copyright  2016 LibreNMS, Barbarossa
 * @license    GPL
 * @package    LibreNMS
 * @subpackage Authentication
 *
 * This Authentitation / Authorization module provides the ability to let
 * the webserver (e.g. Apache) do the user Authentication (using Kerberos
 * f.e.) and let libreNMS do the Authorization of the already known user.
 * Authorization and setting of libreNMS user level is done by LDAP group
 * names specified in the configuration file. The group configuration is
 * basicly copied from the existing ldap Authentication module.
 *
 * Most of the code is copied from the http-auth and ldap Authentication
 * modules already existing.
 *
 * To save lots of redundant queries to the LDAP server and speed up the
 * libreNMS WebUI, all information is cached within the PHP $_SESSION as
 * long as specified in $config['auth_ldap_cache_ttl'] (Default: 300s).
 */

namespace LibreNMS\Authentication;

use LibreNMS\Config;
use LibreNMS\Exceptions\AuthenticationException;

class LdapAuthorizationAuthorizer extends LdapAuthorizer
{
    protected static $AUTH_IS_EXTERNAL = 1;

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

        /*
         * Don't cache that user doesn't exists as this might be a misconfiguration
         * on some end and the user will be happy if it "just works" after the user
         * has been added to LDAP.
         */
        return 0;
    }


    public function getUserlevel($username)
    {
        $userlevel = $this->authLdapSessionCacheGet('userlevel');
        if ($userlevel) {
            return $userlevel;
        } else {
            $userlevel = parent::getUserlevel($username);
        }

        $this->authLdapSessionCacheSet('userlevel', $userlevel);
        return $userlevel;
    }



    public function getUserid($username)
    {
        $user_id = $this->authLdapSessionCacheGet('userid');
        if (isset($user_id)) {
            return $user_id;
        } else {
            $user_id = parent::getUserid($username);
        }

        $this->authLdapSessionCacheSet('userid', $user_id);
        return $user_id;
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

        $cache[$attr]['value'];
    }


    protected function authLdapSessionCacheSet($attr, $value)
    {
        $_SESSION['auth_ldap'][$attr]['value'] = $value;
        $_SESSION['auth_ldap'][$attr]['last_updated'] = time();
    }
}
