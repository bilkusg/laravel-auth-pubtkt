<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Auth\CanResetPassword  as CanResetPasswordContract;
use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Str;

/**
 * This user class extends the default user class to work with pubktk:
 * - rename the email and name fields (to demonstrate how to use aliases in a model for consistency with pubtkt conventions)
 * - implement a user_privileges field which is a set of privileges used to define authorisation 
 * - Add helper methods to interpret user_privileges
 */

class User extends Authenticatable  implements MustVerifyEmail,CanResetPasswordContract
{
    use HasFactory, Notifiable, CanResetPassword;
    protected $table = 'users'; 
    protected $primaryKey = 'user_id'; // default is id
    //public $incrementing = false; // default
    //protected $keyType = 'int'; // default
    public $timestamps = true; // default is true and we now have the necessary fields;
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
      'name',
      'email',
      'user_name',
      'user_email',
      'user_firstname',
      'user_lastname',
      'user_password_hash',
      'user_privileges',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
      'user_password_hash',
    ];
    protected $maps = [
      'user_email' => 'email',
      'user_name' => 'name',
    ];

    protected $appends = [
      'email', 'name',
    ];
  
    public function getEmailAttribute() {
      return $this->attributes['user_email'];
    }
    public function getNameAttribute() {
      return $this->attributes['user_name'];
    }
    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
    ];

      /**
   * {@inheritDoc}
   * @see \Illuminate\Contracts\Auth\Authenticatable::getAuthIdentifierName()
   */
  public function getAuthIdentifierName()
  {
    return "user_email";
  }
  
  /**
   * {@inheritDoc}
   * @see \Illuminate\Contracts\Auth\Authenticatable::getAuthIdentifier()
   */
  public function getAuthIdentifier()
  {
    return $this->{$this->getAuthIdentifierName()};
  }
 
  /**
   * {@inheritDoc}
   * @see \Illuminate\Contracts\Auth\Authenticatable::getAuthPassword()
   */
  public function getAuthPassword()
  {
    return $this->user_password_hash;
  }


  /**
   * {@inheritDoc}
   * @see \Illuminate\Contracts\Auth\Authenticatable::getRememberToken()
   */
  public function getRememberToken()
  {
    if (! empty($this->getRememberTokenName())) {
      return $this->{$this->getRememberTokenName()};
    }
  }
 
  /**
   * {@inheritDoc}
   * @see \Illuminate\Contracts\Auth\Authenticatable::setRememberToken()
   */
  public function setRememberToken($value)
  {
    if (! empty($this->getRememberTokenName())) {
      $this->{$this->getRememberTokenName()} = $value;
    }
  }
 
  /**
   * {@inheritDoc}
   * @see \Illuminate\Contracts\Auth\Authenticatable::getRememberTokenName()
   */
  public function getRememberTokenName()
  {
    return 'user_rememberme_token';
  }

  public function routeNotificationFor($driver, $notification = null)
    {
        switch ($driver) {
            case 'database':
                return $this->notifications();
            case 'mail':
                return $this->email;
        }
    }
    /* from here on are our own model functions unrelated to laravel */
    public function isVerified() : bool
    {
      return (true == $this->email_verified_at);
    }
    public function isAdministrator() : bool
    {
     
        if (strpos($this->user_privileges, 'administrator') !== false) {
            return true;
        }
        return false;
    }
    public function isManager() : bool
    {
        if ($this->isAdministrator()) {
            return true;
        }

        if (strpos($this->user_privileges, 'manager') !== false) {
            return true;
        }
        return false;
    }
    public function isEditor() : bool
    {
        if ($this->isManager()) {
            return true;
        }

        if (strpos($this->user_privileges, 'wikiedit') !== false) {
            return true;
        }
        return false;
    }
    public function isCommittee() : bool
    {
        if (strpos($this->user_privileges, 'committee') !== false) {
            return true;
        }
        return false;
    }
    public function isMember() : bool
    {
    
        if (strpos($this->user_privileges, 'activemember') !== false) {
            return true;
        }
        if (strpos($this->user_privileges, 'staffmember') !== false) {
            return true;
        }
        return false;
    }
}
