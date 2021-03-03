<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;
use App\Http\Controllers\PubtktAdminController;
use App\Http\Controllers\PubtktEditorController;
use Illuminate\Http\Request;
use App\Services\Feedback;
/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return Inertia::render('Welcome', [
        'canLogin' => Route::has('login'),
        'canRegister' => Route::has('register'),
        'laravelVersion' => Application::VERSION,
        'phpVersion' => PHP_VERSION,
    ]);
});
// We show a different dashboard depending on the user
Route::get('/dashboard', function () {
    $user = \Illuminate\Support\Facades\Auth::User();
    if (!$user) {
        // we are not logged in at all
        return redirect('/login');
    } else if (!$user->isVerified()) {
        // our account needs email address verification to complete
        return redirect('/verify-email');
    } else if ($user->isManager()) {
        // we are a manager
        return Inertia::render('ManagerDashboard');
    } else if ($user->isMember()) {
        // we are a member
        return Inertia::render('MemberDashboard');
    } 
    // we are registered but without any particular role or privilege
    return Inertia::render('Dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');


// Our default route is the base url. We require the user be logged in and redirect otherwise
// Then, depending on whether the user has validated their email address, and what roles they have
// we display a suitable menu

// Note that the standard middleware for all these routes includes the default authentication
// which is the Pubtkt one.
require __DIR__.'/auth.php'; // include the authentication pages
// The home route shows an easy way to conditionally display content depending on privileges
//  Of course these checks could be done internally inside a view for fine-grained effects
//  probably inside an @auth condition
Route::get('/home', function () {
    $user = \Illuminate\Support\Facades\Auth::User();
    if (!$user) {
        // we are not logged in at all
        return redirect('/login');
    } else if (!$user->isVerified()) {
        // our account needs email address verification to complete
        return redirect('/verify-email');
    } else if ($user->isManager()) {
        // we are a manager
        return Inertia::render('ManagerDashboard');
    } else if ($user->isMember()) {
        // we are a member
        return Inertia::render('MemberDashboard');
    } 
    // we are registered but without any particular role or privilege
    return Inertia::render('Dashboard');
})->name('home');

// This route shows how to use our middleware guards. If we aren't logged in with member privileges we are sent back
// to login again
Route::get('/member', function () {
    return Inertia::render('MemberDashboard');
})->middleware(['auth','verified','member'])->name('dashboard');
