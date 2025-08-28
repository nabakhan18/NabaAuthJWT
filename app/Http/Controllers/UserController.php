<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
// use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        // $this->authorizeUser();
        $perPage = $request->get('per_page', 10);
        $users = User::orderBy('id', 'asc')->cursorPaginate($perPage);
        return response()->json($users, 200);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    public function edit(string $id)
    {
        //
    }
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'full_name'     => 'required|string|max:40|min:3|',
            'email'    => 'required|string|unique:users',
            // 'password'    => 'required|string|',
            'ref_id'    => 'required|string|',
            'password' => 'required|string|min:6',
        ]);
        // $validator = Validator::make($request->all(), [
        //     'name'     => 'required|string|max:255',
        //     'email'    => 'required|email|unique:users',
        //     'password' => 'required|string|min:6',
        // ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        $User = User::create([
            'full_name'     => $request->full_name,
            'email'    => $request->email,
            // 'password'    => $request->password,
            'ref_id'    => $request->ref_id,
            'password' => Hash::make($request->password),
            // 'is_active' => $request->is_active,
        ]);
        // $token = JWTAuth::fromUser($user);
        // return response()->json([
        //     'user'  => $user,
        //     'token' => $token
        // ], 201);
        return response()->json([
            'User'  => $User,
        ], 201);
    }


    /**
     * Display the specified resource.
     */
    public function show($id)
    {
        // $this->authorizeUser();
        $user = User::find($id);
        if (!$user) return response()->json(['message' => 'User not found'], 404);
        return response()->json($user, 200);
    }


    /**
     * Show the form for editing the specified resource.
     */
    // public function edit(User $user)
    // {
    //     return response()->json([
    //         'message' => 'User data for editing',
    //         'data' => $user
    //     ], 200);
    // }



    /**
     * Update the specified resource in storage.
     */
    // public function update(Request $request, string $id)
    // {
    //     //
    //     $request->validate([
    //         'full_name' => 'required|string|max:255',
    //         // 'ref_id'    => 'sometimes|nullable|string|max:255',
    //         'email'     => 'required|string|email|max:255|unique:users,email',
    //         'password'  => 'required|string|min:8|confirmed',
    //     ]);

    //     $user = User::find($id);
    //     $user->update($request->all());
    //     return response()->json($user);
    // }
    public function update(Request $request, $id)
    {
        // $this->authorizeUser();
        $validator = Validator::make($request->all(), [
            'full_name'     => 'required|string|max:255',
            'email'    => 'required|email',
            'password' => 'required|string|min:6',
            'ref_id' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        $user = User::find($id);

        if (!$user) return response()->json(['message' => 'User not found'], 404);



        // if ($request->filled('password')) {
        //     $request->merge(['password' => Hash::make($request->password)]);
        // } else {
        //     $request->replace($request->except('password'));
        // }
        // $user->update($request->all());
        $user->full_name = $request->full_name;
        $user->email = $request->email;
        $user->password = $request->password;
        $user->ref_id = $request->ref_id;
        $user->update();
        return response()->json($user, 200);
    }

    /**
     * Remove the specified resource from storage.
     */
    // public function destroy(string $id)
    // {
    //     //
    //     $user = User::find($id);
    //     $deletedUser = $user;
    //     $user->delete();
    //     return response()->json(
    //         $deletedUser,
    //         204
    //     );
    // }
    public function destroy($id)
    {
        // $this->authorizeUser();
        $user = User::find($id);
        if (!$user) return response()->json(['message' => 'User not found'], 404);
        $deletedUser = $user;
        $user->delete();
        return response()->json(['data' => $deletedUser, 'message' => 'User deleted successfully'], 200);
    }
    public function login(Request $request)
    {
        // Validate input
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        // Find user by email
        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Account does not exist with email ' . $request->email
            ], 404);
        }

        // Check password
        if (!Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid username or password.'
            ], 401);
        }
        $credentials = $request->only('email', 'password');

        //     if (!$token = JWTAuth::attempt($credentials)) {
        //         return response()->json(['message' => 'Invalid email or password'], 401);
        //     }
        //     //Success
        //     return response()->json([
        //         'status' => true,
        //         'message' => 'Login successful',
        //         'user' => $user,
        //         'token' => $token,
        //     ], 200);
        // }

        // public function login(Request $request)
        // {
        //    

        //     return response()->json([
        //         'token' => $token,
        //         'user'  => auth()->user()
        //     ]);
        // }

        /**
         * Helper to ensure user is logged in.
         */
        // private function authorizeUser()
        // {
        //     try {
        //         if (! $user = JWTAuth::parseToken()->authenticate()) {
        //             abort(404, 'User not found');
        //         }
        //     } catch (\Exception $e) {
        //         abort(401, 'Unauthorized');
        //     }
        // }
    }
}
