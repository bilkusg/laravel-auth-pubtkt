<?php
/*
Generate tickets for use with mod_auth_pubtkt
(https://neon1.net/mod_auth_pubtkt)

written by Manuel Kasper <mk@neon1.net>
Modified by Gary Bilkus
Now uses php built-in openssl methods rather than external programs
and eliminates unused functions. Also adds in helper functions for interface
with Laravel
 */

namespace App\Services\Auth;

class Pubtkt
{
    public static function pubtkt_sign_ticket($privkeyfile, $privkeytype, $tkt)
    {

        if ($privkeytype == "DSA") {
            $algoparam = OPENSSL_ALGO_DSS1;
        } else {
            $algoparam = OPENSSL_ALGO_SHA1;
        }

        $privkey = file_get_contents($privkeyfile);
        if (openssl_sign($tkt, $sig, $privkey, $algoparam) === false) {
            echo "openssl_sign failed";
            return false;
        }
        //error_log("class based pubtkt_generate OK ".$tkt);
        $signedTkt = $tkt . ";sig=" . base64_encode($sig);
        //error_log("pubtkt_generate:".$signedTkt);
        return $signedTkt;
    }
// After a ticket is validated we may want to remove the signature part before parsing the underlying data
    public static function pubtkt_remove_signature($tkt)
    {
        $pos = strrpos($tkt, ";sig=");
        return substr($tkt, 0, $pos);

    }
// Takes a ticket with a signature, validates it and parses the underlying data as json into a php result
    public static function pubtkt_greenwheel_data($pubkeyfile, $keytype, $cookie2)
    {

        $cookie2_verified = Pubtkt::pubtkt_verify($pubkeyfile, $keytype, $cookie2);
        if ($cookie2_verified) {

            $c2 = Pubtkt::pubtkt_remove_signature($cookie2);
            $result = json_decode($c2);
            return $result;
        };
        return null;
    }
/* Generate an auth ticket from the values it holds

Parameters:
privkeyfile        path to private key file (PEM format)
privkeytype        type of private key ("RSA" or "DSA")
uid                user ID/username
clientip        client IP address (optional; can be empty or null)
validuntil        expiration timestamp (e.g. time() + 86400)
tokens            comma-separated list of tokens (optional)
udata            user data (optional)
bauth            basic auth username:password (for passthru, optional;
can optionally use pubtkt_encrypt_bauth() to encrypt it)

Returns:
ticket string, or FALSE on failure
 */
    public static function pubtkt_generate($privkeyfile, $privkeytype, $uid, $clientip, $validuntil, $graceperiod, $tokens, $udata, $bauth = null)
    {

        /* format ticket string */
        $tkt = "uid=$uid;";
        if ($clientip) {
            $tkt .= "cip=$clientip;";
        }

        $tkt .= "validuntil=$validuntil;";
        if (isset($graceperiod) && is_numeric($graceperiod) && $graceperiod > 0) {
            $tkt .= "graceperiod=" . ($validuntil - $graceperiod) . ";";
        }
        if (!empty($bauth)) {
            $tkt .= "bauth=" . base64_encode($bauth) . ";";
        }

        $tkt .= "tokens=$tokens;udata=$udata";
        return Pubtkt::pubtkt_sign_ticket($privkeyfile, $privkeytype, $tkt);
    }

/*    Validate a ticket.

Parameters:
pubkeyfile        path to public key file (PEM format)
pubkeytype        type of public key ("RSA" or "DSA")
ticket            ticket string (including signature)

Returns:
ticket valid true/false
 */
    public static function pubtkt_verify($pubkeyfile, $pubkeytype, $ticket)
    {
        /* strip off signature */
        $sigpos = strrpos($ticket, ";sig=");
        if ($sigpos === false) {
            return false;
        }
        /* no signature found */

        $ticketdata = substr($ticket, 0, $sigpos);
        $sigdata = base64_decode(substr($ticket, $sigpos + 5));

        if (!$sigdata) {
            return false;
        }

        /* write binary signature to temporary file */

        if ($pubkeytype == "DSA") {
            $algoparam = OPENSSL_ALGO_DSS1;
        } else {
            $algoparam = OPENSSL_ALGO_SHA1;
        }

        $pubkey = file_get_contents($pubkeyfile);
        return (openssl_verify($ticketdata, $sigdata, $pubkey, $algoparam) == 1);
    }

/*    Parse a standard ticket into its key/value pairs and return them as an
associative array for easier use.
 */
    public static function pubtkt_parse($ticket)
    {
        $tkt = array();
        $kvpairs = explode(";", $ticket);

        foreach ($kvpairs as $kvpair) {
            list($key, $val) = explode("=", $kvpair, 2);
            $tkt[$key] = $val;
        }

        return $tkt;
    }
    public static function currentSsoUser()
    {
        $pubkeyfile=env("SSO_PUBKEY");
        $keytype="RSA";
        $pubtktCookieName="auth_pubtkt";
        $greenwheelCookieName="auth_greenwheel";

        if (!isset($_COOKIE[$pubtktCookieName])) {
            return null;
        }
        if (!isset($_COOKIE[$greenwheelCookieName])) {
            return null;
        }
        $cookie = $_COOKIE[$pubtktCookieName];
        $verified = Pubtkt::pubtkt_verify($pubkeyfile, $keytype, $cookie);
        if (!$verified) {
            // we have a bad pubtkt cookie - get rid of it
            self::unsetSsoUser();
            return null;
        }
        $tktinfo = Pubtkt::pubtkt_parse($cookie);
        $cookie2 = $_COOKIE[$greenwheelCookieName];
        $result = Pubtkt::pubtkt_greenwheel_data($pubkeyfile, $keytype, $cookie2);
        // Now we check for consistency etc
        $validuntil = $tktinfo['validuntil'];
        $graceperiod = $tktinfo['graceperiod'];
        $now = time();

        if ( ($validuntil )< $now ) // ticket has expired
        {
            self::unsetSsoUser();
            return null;
        }
        
        return $result;
    }
    public static function unsetSsoUser() 
    {
        $pubtktCookieName="auth_pubtkt";
        $greenwheelCookieName="auth_greenwheel";
        $domain = env('SSO_DOMAIN');
        setcookie($pubtktCookieName, "", time() - 86400, "/",$domain , true);
        setcookie($greenwheelCookieName, "", time() - 86400, "/", $domain, true);
    }
    public static function setSsoUser($user,$user_id,$user_name,$tokens)
    {
        $pubkeyfile=env("SSO_PUBKEY");
        $keytype="RSA";
        $pubtktCookieName="auth_pubtkt";
        $greenwheelCookieName="auth_greenwheel";
        $privkeyfile=env("SSO_PRIVKEY");
        $domain=env("SSO_DOMAIN");
        $json = json_encode($user);
        $default_timeout = 12*3600; // 12 hours - is this a decent balance between security and convenience?
        $default_graceperiod = $default_timeout; // we don't handle token refreshes without revalidation
        $tkt_validuntil = time() + $default_timeout;
        $tkt_graceafter = time() + $default_graceperiod;
        $udata = "username=" . $user_name . ":";
        /* generate the ticket now and set a domain cookie */
        $tkt = Pubtkt::pubtkt_generate($privkeyfile, $keytype, $user_id,
            $_SERVER['REMOTE_ADDR'], $tkt_validuntil, $tkt_graceafter, $tokens, $udata);
        setcookie("auth_pubtkt", $tkt, 0, "/", $domain,true,true);
        $tkt2 = Pubtkt::pubtkt_sign_ticket($privkeyfile, $keytype, $json);
        setcookie("auth_greenwheel", $tkt2, 0, "/", $domain,true,true);

    }
}
