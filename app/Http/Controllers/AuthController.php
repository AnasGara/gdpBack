<?php

namespace App\Http\Controllers;

use App\Models\User;
use Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Cookie;

class AuthController extends Controller
{
    //
    public function user()
    {
        return Auth::user();

    }

    public function register(Request $request)
    {
        return User::create(
            [
                'name' => $request->input('name'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password'))
            ]
        );
    }
    public function login(Request $request)
    {
        //if not valid
        if (
            !Auth::attempt($request->only('email', 'password'))
        ) {
            return response(
                [
                    'message' => 'Invalid Credentials'
                ],
                Response::HTTP_UNAUTHORIZED
            );
        }
        //if auth valid
        $user = Auth::user();

        $token = $user->createToken('token')->plainTextToken;

        //$user->token = $token;

        $cookie = cookie('jwt', $token, 60 * 8);

        return response([
            'message' => 'Successfully Logged '
        ])->withCookie($cookie);
        ;
    }

    public function logout()
    {
        $cookie = Cookie::forget('jwt');

        return response([
            'message' => 'Success'
        ])->withCookie($cookie);
    }
}
