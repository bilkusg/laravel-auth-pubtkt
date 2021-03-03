<x-guest-layout>
    <x-auth-card>
        <!-- Validation Errors -->
        <x-auth-validation-errors class="mb-4" :errors="$errors" />

        <form method="POST" action="{{ route('register') }}">
            @csrf

            <!-- Name -->
            <x-field>
                <x-label for="name" :value="__('Enter your preferred User Name')" />

                <x-input id="name" class="block mt-1 w-full" type="text" name="name" :value="old('name')" required autofocus />
            </x-field>

            <!-- Email Address -->
            <x-field class="mt-4">
                <x-label for="email" :value="__('Email')" />

                <x-input id="email" class="block mt-1 w-full" type="email" name="email" :value="old('email')" required />
            </x-field>
            <x-field>
                <x-label for="user_firstname" :value="__('Enter First Name')" />

                <x-input id="user_firstname" class="block mt-1 w-full" type="text" name="user_firstname" :value="old('user_firstname')" required autofocus />
            </x-field>
            <x-field>
                <x-label for="user_lastname" :value="__('Enter Last Name')" />

                <x-input id="user_lastname" class="block mt-1 w-full" type="text" name="user_lastname" :value="old('user_lastname')" required autofocus />
            </x-field>

            <!-- Password -->
            <x-field class="mt-4">
                <x-label for="password" :value="__('Password')" />

                <x-input id="password" class="block mt-1 w-full"
                                type="password"
                                name="password"
                                required autocomplete="new-password" />
            </x-field>

            <!-- Confirm Password -->
            <x-field class="mt-4">
                <x-label for="password_confirmation" :value="__('Confirm Password')" />

                <x-input id="password_confirmation" class="block mt-1 w-full"
                                type="password"
                                name="password_confirmation" required />
            </x-field>

            <x-field class="">
                <a class="button" class="" href="{{ route('login') }}">
                    {{ __('Already registered?') }}
                </a>

                <x-button class="button is-primary">
                    {{ __('Register') }}
                </x-button>
            </x-field>
        </form>
    </x-auth-card>
</x-guest-layout>
