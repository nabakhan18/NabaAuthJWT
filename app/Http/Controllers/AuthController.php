<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Illuminate\Http\JsonResponse;

class AuthController extends Controller
{
    // Register
public function register(Request $request)
{
    // Manually trim and sanitize email
    $request->merge([
        'email' => trim($request->email),
    ]);

    // Check if user already exists
    if (User::where('email', $request->email)->exists()) {
        return response()->json([
            'message' => 'User already registered.'
        ], 409); // 409 = Conflict
    }

    // Validation rules
    $validator = validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => [
            'required',
            'email',
            'regex:/^[^\s@]+@[^\s@]+\.[^\s@]+$/',
        ],
        'password' => 'required|string|min:8',
    ], [
        'email.regex' => 'The email must not contain spaces.',
        'email.email' => 'The email format is invalid.',
        'password.min' => 'The password must be at least 8 characters.',
    ]);

    // Handle failed validation
    if ($validator->fails()) {
        return response()->json([
            'message' => 'We cant register, correct your format',
            'errors' => $validator->errors()
        ], 422);
    }

    // Create user
    $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => bcrypt($request->password),
    ]);

    return response()->json([
        'message' => 'User registered successfully.',
        'user' => $user,
    ], 201);
}
    // Login
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        return response()->json([
            'token' => $token
        ]);
    }

public function logout(Request $request)
{
    try {
        $token = JWTAuth::getToken();

        // If no token was sent at all
        if (!$token) {
            return response()->json([
                'message' => 'Token not provided.'
            ], 400);
        }

        // Invalidate the token (logout)
        JWTAuth::invalidate($token);

        return response()->json([
            'message' => 'Successfully logged out.'
        ], 200);

    } catch (TokenExpiredException $e) {
        return response()->json([
            'message' => 'Token has already expired.'
        ], 401);

    } catch (TokenInvalidException $e) {
        return response()->json([
            'message' => 'Token is invalid.'
        ], 401);

    } catch (JWTException $e) {
        return response()->json([
            'message' => 'Could not log out. Something went wrong with the token.'
        ], 500);
    }
}


    // Refresh token
    public function refresh()
    {
        $newToken = JWTAuth::refresh(JWTAuth::getToken());

        return response()->json([
            'token' => $newToken
        ]);
    }

    // Get current user
public function me()
{
    $user = Auth::guard('api')->user();

    if (!$user) {
        return response()->json([
            'message' => 'Unauthenticated. Token is missing, invalid, or expired.'
        ], 401); // 401 Unauthorized
    }

    return response()->json($user);
}
}
