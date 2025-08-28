<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class RoleMiddleware
{
    public function handle(Request $request, Closure $next, $role)
    {
        try {
            // Get the authenticated user via JWT
            $user = JWTAuth::parseToken()->authenticate();

            // If no user or role mismatch
            if (!$user || $user->role !== $role) {
                return response()->json(['error' => 'Unauthorized - role mismatch'], 403);
            }

        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized - invalid token'], 401);
        }

        return $next($request);
    }
}
