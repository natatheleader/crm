<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\Api\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::controller(AuthController::class)->group(function () {
    Route::post('v1/auth/loginEmail', 'loginEmail')->name('loginEmail');
    Route::post('v1/auth/registerEmail', 'registerEmail');
    Route::get('v1/auth/resendVerificationLink', 'resendVerificationLink');
    Route::post('v1/auth/logout', 'logout');
    Route::post('v1/auth/refresh', 'refresh');
    Route::post('v1/auth/forgetPassword', 'forgetPassword');
    Route::post('v1/auth/resetPassword', 'resetPassword');
    Route::get('v1/auth/verifyEmail/{token}', 'verifyEmail');
    // Route::post('v1/auth/sendOTPLogin', 'loginSendOTP');
    // Route::post('v1/auth/OTPLogin', 'loginPhone');
    // Route::post('v1/auth/OTPRegister', 'registerPhone');
    // Route::post('v1/auth/RegisterVerifyOTP', 'verifyOTPRegister');
    // Route::post('v1/auth/resendOTP', 'resendOTP');
});

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
