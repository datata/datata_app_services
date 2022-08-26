<?php

namespace App\Http\Controllers;

use App\Mail\ActivateAccountMail;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    const ROLE_ADMIN = 2;

    public function register(Request $request)
    {
        try {
            Log::info("Register");

            
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:100',
                'email' => 'required|string|email|max:100|unique:users',
                'password' => 'required|string|min:6',
            ]);
            
            if ($validator->fails()) {
                return response()->json(
                    [
                        "success" => false,
                        "error" => $validator->errors()
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }
            
            DB::beginTransaction();
            $email = $request->get('email');
            $name = $request->get('name');
            $hash = md5(rand(0, 1000));

            $user = User::create([
                'name' => $name,
                'email' => $email,
                'password' => bcrypt($request->password),
                'hash' => $hash
            ]);

            $user->roles()->attach(self::ROLE_ADMIN);

            // $token = JWTAuth::fromUser($user);

            Mail::to($email)->send(new ActivateAccountMail(
                $name,
                $email,
                $hash,
                env('APP_URL')
            ));

            DB::commit();

            return response()->json(
                [
                    "success" => true,
                    "user" => $user,
                    // "token" => $token
                ],
                Response::HTTP_CREATED
            );
        } catch (\Exception $exception) {
            Log::error('Error register user -> ' . $exception->getMessage());
            DB::rollBack();

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot be registered'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    public function login(Request $request)
    {
        try {
            Log::info('Login');

            $input = $request->only('email', 'password');
            $jwtToken = null;

            if (!$jwtToken = JWTAuth::attempt($input)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid Email or Password',
                ], Response::HTTP_UNAUTHORIZED);
            }

            $user = User::query()
                ->where('email', $request->input('email'))
                ->where('is_active', true)
                ->first();;

            if (!$user) {
                throw new Exception('Account is not activated');
            }

            return response()->json([
                'success' => true,
                'token' => $jwtToken,
            ]);
        } catch (\Exception $exception) {
            Log::error('Error register user -> ' . $exception->getMessage());

            if ($exception->getMessage() === 'Account is not activated') {
                return response()->json(
                    [
                        'success' => false,
                        'message' => 'You must activate your account first'
                    ],
                    Response::HTTP_UNAUTHORIZED
                );
            }

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot be loggued'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    public function me()
    {
        Log::info('Profile');

        return response()->json(
            [
                "success" => true,
                "message" => "User data",
                "data" => auth()->user()
            ]
        );
    }

    public function logout(Request $request)
    {
        $this->validate($request, ['token' => 'required']);

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (\Exception $exception) {
            Log::error('Error logout -> ' . $exception->getMessage());

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot be logged out'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    public function activeUser(Request $request)
    {
        try {
            Log::info('Validating account.');

            if (!$request->query('hash') || !$request->query('email')) {
                return response()->json(
                    [
                        'success' => false,
                        'message' => 'Invalid route'
                    ],
                    Response::HTTP_BAD_GATEWAY
                );
            }

            $hash = $request->query('hash');
            $email = str_replace('[at]', '@', $request->query('email'));

            $activeUser = User::query()
                ->where('hash', $hash)
                ->where('email', $email)
                ->where('is_active', false)
                ->first();;

            if (!$activeUser) {
                return response()->json(
                    [
                        'success' => false,
                        'message' => 'You account is already activated'
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }

            $activeUser->is_active = true;
            $activeUser->save();

            return response()->json(
                [
                    'success' => true,
                    'message' => 'User account activated successfully'
                ],
                Response::HTTP_ACCEPTED
            );
        } catch (\Exception $exception) {
            Log::error('Error validating account -> ' . $exception->getMessage());

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user account cannot activated'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }
}
