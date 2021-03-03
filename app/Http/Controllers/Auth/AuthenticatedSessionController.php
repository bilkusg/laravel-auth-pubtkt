<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     *
     * @return \Illuminate\View\View
     */
    public function create(Request $request)
    {
        // For auth_pubtkt we allow a back parameter to determine where we go next
        if ($request->filled('back')) {
            $request->session()->put('back',$request->back);
        }

        return Inertia::render('Auth/Login', [
            'canResetPassword' => Route::has('password.request'),
            'status' => session('status'),
        ]);
    }

    /**
     * Handle an incoming authentication request.
     *
     * @param  \App\Http\Requests\Auth\LoginRequest  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function store(LoginRequest $request)
    {
        $request->authenticate();

        $request->session()->regenerate();
        $back = $request->session()->get('back',null);
        // For auth_pubtkt we allow a back parameter to determine where we go next
        if ($back)
        {
            return Inertia::location($back);
        }

        return redirect()->intended(RouteServiceProvider::HOME);
    }

    /**
     * Destroy an authenticated session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function destroy(Request $request)
    {
        // For auth_pubtkt we allow a back parameter to determine where we go next
        $back = '/';
        if ($request->filled('back')) {
            $back = $request->back;
        }
        Auth::guard('pubtkt')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();
        if ($request->filled('back')) {
            redirect($request->back);
        }
        if ($back) {
            return Inertia::location($back);
        }
        return redirect('/');
    }
}
