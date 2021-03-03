<?php
namespace App\Services\Auth;
use Illuminate\Http\Request;
use \Illuminate\Contracts\Auth\Authenticatable;
use \Illuminate\Contracts\Auth;
use \Illuminate\Contracts\Auth\StatefulGuard;
use \Illuminate\Auth\GuardHelpers;
use \Illuminate\Contracts\Auth\UserProvider;
use \Illuminate\Contracts\Session\Session;
use \App\Models\User;

// See Auth/SessionGuard.php for starting point
class PubtktGuard implements StatefulGuard 
{
    use GuardHelpers;

    protected $session;
    protected $request;
    protected $provider;
    
    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;
    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    public function __construct( $provider, Request $request = null)
    {
        $this->request = $request;
        if ($request->hasSession()) 
        {
            $this->session = $request->session();
        } else 
        {
            $this->session = null;
        }
        $this->provider = $provider;
    }

     /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }
        // If we already have a user set and haven't logged out in this request already then good.
        if (!is_null($this->user)) return $this->user;

        // See if we are logged in using sso
        $ssouser =  Pubtkt::currentSsoUser();

        if (!is_null($ssouser)) { 
            $this->user = $this->provider->retrieveById($ssouser->user_email);
            return $this->user;
        }
        // Last chance - do we have a registered but unconfirmed user in play
        if ($this->session) {
            $id = $this->session->get('pubtkt-unconfirmed-user');
            if (! is_null($id)) {
                $this->user = $this->provider->retrieveById($id);
                return $this->user;
             }
        }
        return;
    }
         /**
     * Return the currently cached user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param  Array $user User info
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
        $this->loggedOut = false;
        return $this;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return string|null
     */
    public function id()
    {
        return $this->user() ?
            $this->user()-getAuthIdentifier() :
            null;
    }

   /**
     * Log a user into the application without sessions or cookies.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param  mixed  $id
     * @return \Illuminate\Contracts\Auth\Authenticatable|false
     */
    public function onceUsingId($id)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return $user;
        }
        return false;
    }

     /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user,$credentials);
    }

    public function attempt(Array $credentials=[],$remember=false)
    {
        $this->lastAttemplted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user,$credentials))
        {
            $this->login($user);
            return true;
        }
        Pubtkt::unsetSsoUser(); // remove cookies if login fails
        return false;
    }
    
    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        $validated = ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
        return $validated;
    }

    /**
     * Log the given user ID into the application.
     *
     * @param  mixed  $id
     * @param  bool  $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable|false
     */
    public function loginUsingId($id, $remember = false)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    public function login(Authenticatable $user, $remember = false)
    {
        $this->setUser($user);
        $user->user_last_login_timestamp = time();
        $user->save();
        $ssoUser = new \StdClass();
        $ssoUser->user_id = $user->user_id;
        $ssoUser->user_name = $user->user_name;
        $ssoUser->user_email = $user->user_email;
        $ssoUser->user_firstname = $user->user_firstname;
        $ssoUser->user_lastname = $user->user_lastname;
        $ssoUser->user_privileges = $user->user_privileges;
        if ($user->email_verified_at) {
            Pubtkt::setSsoUser($ssoUser, $this->user->user_id, $this->user->user_name, $this->user->user_privileges);
            $this->session->put('pubtkt-unconfirmed-user',null);
        } else { // valid user but hasn't yet confirmed their email address
            $this->session->put('pubtkt-unconfirmed-user',$user->getAuthIdentifier());
        }
        return;
    }
    
    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        Pubtkt::unsetSsoUser();

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    public function viaRemember()
    {
        return false;
    }
    /* now the helper functions for the ticket creation etc
     * largely based on published sample code in auth_pubtkt docs
     */
}                                                             
?>
