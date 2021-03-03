<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Auth;

// Modified to register these home-produced classes
use App\Services\Auth\PubtktGuard;
use App\Extensions\PubtktSsoUserProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [
        // 'App\Models\Model' => 'App\Policies\ModelPolicy',
    ];

    /**
     * Register any authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();
        // This is the stateful guard for Pubtkt which looks for an auth_pubtkt cookie
        Auth::extend('pubtkt', function ($app, $name, array $config) {
            // Return an instance of Illuminate\Contracts\Auth\Guard...
            return new PubtktGuard(Auth::createUserProvider($config['provider']),$app->make('request')); //Auth::createUserProvider($config['provider']));
        });
        // This is the provider for Pubtkt which creates an auth_pubtkt cookie after validating a user from the database
        Auth::provider('pubtktsso', function($app,array $config){
            return new PubtktSsoUserProvider( $app['hash'], 'App\Models\User');
        });
    }
}
