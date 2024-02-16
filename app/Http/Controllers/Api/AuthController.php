<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
// use App\Models\Referral;
use Carbon\Carbon; 
use Mail;
use DB;
use Auth;
use Validator;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;

class AuthController extends BaseController
{
    //
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['loginEmail','registerEmail', 'forgetPassword', 'resetPassword', 'loginSendOTP', 'loginPhone', 'registerPhone', 'verifyOTPRegister', 'verifyEmail', 'resendOTP']]);
    }

    public function loginEmail(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        
        $credentials = $request->only('email', 'password');

        $token = Auth::attempt($credentials);
        
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = Auth::user();

        return response()->json([
            'status' => 'success',
            'user' => $user,
            'profile' => $user->profile,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    public function registerEmail(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'c_password' => 'required|string|min:6|same:password',
            'type'  => 'required'
        ]);

        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }

        if (isset($input['r_code'])) {
            $code = User::where('r_code', $input['r_code']);

            if ($code == null) {
                return $this->sendError('Validation Error.', 'Refferal Code Doesn\'t exist'); 
            }
        }

        $input = $request->all();

        if ($input['type'] == '1') {
            //customer
            $input['is_active'] = true;
        } else if ($input['type'] == '2') {
            //sales
            $input['is_active'] = false;
        } else {
              $input['is_active'] = false;
        }

        $first_part_of_string = substr($input['name'],0,2);
        
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < 7; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }

        $input['referral_code'] = $first_part_of_string . "_" . $randomString;
        
        $user = User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => Hash::make($request->password),
            'type' => $input['type'],
            'is_active' => $input['is_active'],
            'r_code' => $input['referral_code'],
        ]);

        $token = Auth::login($user);

        if ($user->type == 1) {
            $user->assignRole('customer');
        } else if ($user->type == 2) {
            $user->assignRole('sales');
        }

        if (isset($input['r_code'])) {
            $code = User::where('r_code', $input['r_code'])->first();

            $reff = Referral::create([
                'user_id'           => $user->id,
                'reffered_by_id'    => $code->id,
            ]);
        }

        date_default_timezone_set('Africa/Addis_Ababa');

        //send email for activation
        $now = date("Y-m-d H:i:s");
        $endTime = strtotime("+10 minutes", strtotime($now));
        $expires = date("Y-m-d H:i:s", $endTime);

        $verificationToken = Crypt::encryptString($input['email'] . '~' . $now . '~' . $expires);

        try {
            Mail::send('emails.activateAccount', ['token' => $verificationToken], function($message) use($request){
                $message->to($request->email);
                $message->subject('Welcome to ewenet satage! Please activate your Account.');
            });
        } catch (Exeption $e)
        {}

        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            // 'permissions' => $user->getPermissionsViaRoles(),
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    public function resendVerificationLink() 
    {
        $user = Auth::user();

        date_default_timezone_set('Africa/Addis_Ababa');

        //send email for activation
        $now = date("Y-m-d H:i:s");
        $endTime = strtotime("+10 minutes", strtotime($now));
        $expires = date("Y-m-d H:i:s", $endTime);

        $verificationToken = Crypt::encryptString($user->email . '~' . $now . '~' . $expires);

        try {
            Mail::send('emails.activateAccount', ['token' => $verificationToken], function($message) use($user) {
                $message->to($user->email);
                $message->subject('Welcome to ewenet satage! Please activate your Account.');
            });
        } catch (Exeption $e)
        {}

        return response()->json([
            'status' => 'success',
            'message' => 'Email sent successfully.'
        ]);
    }

    // public function loginSendOTP(Request $request) 
    // {
    //     $input = $request->all();

    //     $validator = Validator::make($input, [
    //         'phone'                     => 'required|exists:users,phone',
    //     ]);
        
    //     if($validator->fails()){
    //         return $this->sendError('Validation Error.', $validator->errors());       
    //     }

    //     $otp = $this->generatePIN();
    //     //check the database for otp not to send an already sent otp
    //     $user = User::where('phone', $input['phone'])->first();
    //     if ($user) {
    //         date_default_timezone_set('Africa/Addis_Ababa');

    //         $datetime = date("Y-m-d H:i:s");
    //         $endTime = strtotime("+5 minutes", strtotime($datetime));

    //         $otp_data = [
    //             'user_id'           => $user->id,
    //             'otp'               => $otp,        
    //             'used_for'          => 1,
    //             'expires_at'        => date("Y-m-d H:i:s", $endTime),
    //         ];
            
    //         $created = OTP::create($otp_data);

    //         if ($created) {
    //             //send the otp via SMS
    //             $to = $input['phone'];
    //             $message = $otp;
    //             $template_id = 'otp';
                
    //             try{
    //                 $send = $this->sendSMS($to, $message, $template_id);
    //             } catch (Exception $e)
    //             {
    //                 return $e;
    //             }
    //             //return success
    //             return response()->json([
    //                 'status' => 'success',
    //                 'message' => 'OTP sent successfully.'
    //             ]);
    //         } else {
    //             //return error
    //             $response['error'] = 'Internal Server Error';
    //             $response['message'] = 'Internal server error. Please try again.';
    //             $statusCode = 500;
    //             return response()->json($response, $statusCode);
    //         }
    //     }else {
    //         $response['error'] = 'No Data';
    //         $response['message'] = 'No user found for this phone number.';
    //         $statusCode = 400;
    //         return response()->json($response, $statusCode);
    //     }
    // }

    // public function loginPhone(Request $request)
    // {
    //     date_default_timezone_set('Africa/Addis_Ababa');
    //     $input = $request->all();

    //     $validator = Validator::make($input, [
    //         'phone'     => 'required|exists:users,phone',
    //         'otp'       => 'required',
    //     ]);
        
    //     if($validator->fails()){
    //         return $this->sendError('Validation Error.', $validator->errors());       
    //     }

    //     //check for otp validity and then generate accesstoken
    //     $user = User::where('phone', $input['phone'])->first();
    //     if ($user) {
    //         $otp = OTP::where('otp', $input['otp'])->where('user_id', $user->id)->first();
            
    //         $datetime   = date("Y-m-d H:i:s");
    //         $now        = strtotime($datetime);
            
    //         if ($otp && $otp->used_for == 1 && (strtotime($otp->expires_at) > $now)) {
    //             if ($input['otp'] === $otp->otp) {
    //                 $token = auth()->login($user);

    //                 if (!$token) {
    //                     return response()->json([
    //                         'status' => 'error',
    //                         'message' => 'Unauthorized',
    //                     ], 401);
    //                 }

    //                 if ($user->type == '1') {
    //                     //castee
    //                     $has_paied = false;
    //                 } else if ($user->type == '2') {
    //                     //director
    //                     $has_paied = true;
    //                 } else if ($user->type == '0') {
    //                     //admin
    //                     $has_paied = false;
    //                 }

    //                 $payment = Payment::where('user_id', $user->id)->latest()->first();

    //                 if ($user->type == '2') {
    //                     $has_paied = true;
    //                 } else if (!is_null($payment) && $payment->paied == 1) {
    //                     //check for expiration
    //                     $datetime   = date("Y-m-d");
    //                     $now        = strtotime($datetime);
                        
    //                     if (strtotime($payment->till) > $now) {
    //                         $has_paied = true;
    //                     } 
    //                 } else if (!is_null($payment)) {
    //                     $data = Chapa::verifyTransaction($payment->tx_ref);
                
    //                     if ($data['status'] ==  'success' && $data['data']['amount'] >= $payment->amount) {  
    //                         date_default_timezone_set('Africa/Addis_Ababa');
        
    //                         $datetime = date("Y-m-d");
    //                         $endTime = strtotime("+ " . $payment->for_months . " months", strtotime($datetime));
    //                         $created_at = explode("T", $data['data']['created_at']);
        
    //                         $payment->till = date("Y-m-d", $endTime);
    //                         $payment->paied_date = $created_at[0];
    //                         $payment->paied = true;
    //                         $payment->save();
        
    //                         if ($payment) {
    //                             $has_paied = true;
    //                         } else {
    //                             $has_paied = false;
    //                         }
    //                     } else {
    //                         $has_paied = false;   
    //                     }
    //                 }

    //                 return response()->json([
    //                     'status' => 'success',
    //                     'user' => $user,
    //                     'profile' => $user->profile,
    //                     'has_paied' => $has_paied,
    //                     'permissions' => $user->getPermissionsViaRoles(),
    //                     'authorisation' => [
    //                         'token' => $token,
    //                         'type' => 'bearer',
    //                     ]
    //                 ]);
    //             } else {
    //                 return response()->json([
    //                     'status' => 'error',
    //                     'message' => 'Unauthorized',
    //                 ], 401);
    //             }
    //         } else {
    //             return response()->json([
    //                 'status' => 'error',
    //                 'message' => 'Unauthorized',
    //             ], 401);
    //         }
    //     } else {
    //         return response()->json([
    //             'status' => 'error',
    //             'message' => 'Unauthorized',
    //         ], 401);
    //     }
    // }

    // public function registerPhone(Request $request)
    // {
    //     $validator = Validator::make($request->all(), [
    //         'name' => 'required|string|max:255',
    //         'phone' => 'required|string|unique:users',
    //         'type'  => 'required'
    //     ]);

    //     if($validator->fails()){
    //         return $this->sendError('Validation Error.', $validator->errors());       
    //     }

    //     if (isset($input['r_code'])) {
    //         $code = User::where('r_code', $input['r_code']);

    //         if ($code == null) {
    //             return $this->sendError('Validation Error.', 'Refferal Code Doesn\'t exist'); 
    //         }
    //     }

    //     $input = $request->all();

    //     if ($input['type'] == '1') {
    //         //castee
    //         $input['is_active'] = true;
    //         $input['is_d_verified'] = true;
    //     } else if ($input['type'] == '2') {
    //         //director
    //         $input['is_active'] = false;
    //         $input['is_d_verified'] = false;
    //     } else if ($input['type'] == '0') {
    //         //admin
    //         $input['is_active'] = true;
    //         $input['is_d_verified'] = true;
    //     } else {
    //           $input['is_active'] = true;
    //           $input['is_d_verified'] = true;
    //     }

    //     $first_part_of_string = substr($input['name'],0,2);
        
    //     $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    //     $charactersLength = strlen($characters);
    //     $randomString = '';
    //     for ($i = 0; $i < 7; $i++) {
    //         $randomString .= $characters[random_int(0, $charactersLength - 1)];
    //     }

    //     $input['referral_code'] = $first_part_of_string . "_" . $randomString;

    //     $user = User::create([
    //         'name' => $input['name'],
    //         'phone' => $input['phone'],
    //         'type' => $input['type'],
    //         'is_active' => $input['is_active'],
    //         'is_d_verified' => $input['is_d_verified'],
    //         'r_code' => $input['referral_code'],
    //     ]);

    //     if (isset($input['r_code'])) {
    //         $code = User::where('r_code', $input['r_code'])->first();

    //         $reff = Referral::create([
    //             'user_id'           => $user->id,
    //             'reffered_by_id'    => $code->id,
    //         ]);
    //     }

    //     if ($user) {
    //         $otp = $this->generatePIN();
    //         //check the database for otp not to send an already sent otp

    //         date_default_timezone_set('Africa/Addis_Ababa');

    //         $datetime = date("Y-m-d H:i:s");
    //         $endTime = strtotime("+5 minutes", strtotime($datetime));

    //         $otp_data = [
    //             'user_id'           => $user->id,
    //             'otp'               => $otp,        
    //             'used_for'          => 2,
    //             'expires_at'        => date("Y-m-d H:i:s", $endTime),
    //         ];
            
    //         $created = OTP::create($otp_data);

    //         if ($created) {
    //             //send the otp via SMS
    //             $to = $input['phone'];
    //             $message = $otp;
    //             $template_id = 'otp';
                
    //             try{
    //                 $send = $this->sendSMS($to, $message, $template_id);
    //             } catch (Exception $e)
    //             {
    //                 return $e;
    //             }
    //             //return success
    //             if ($input['type'] == '1') {
    //                 //castee
    //                 $has_paied = false;
    //             } else if ($input['type'] == '2') {
    //                 //director
    //                 $has_paied = true;
    //             } else if ($input['type'] == '0') {
    //                 //admin
    //                 $has_paied = false;
    //             } else {
    //                 $has_paied = false;
    //             }

    //             $payment = Payment::where('user_id', $user->id)->first();

    //             if ($input['type'] == '2') {
    //                 $has_paied = true;
    //             } else if (!is_null($payment) && $payment->paied == 1) {
    //                 //check for expiration
    //                 $datetime   = date("Y-m-d");
    //                 $now        = strtotime($datetime);
                    
    //                 if (strtotime($payment->till) > $now) {
    //                     $has_paied = true;
    //                 }
    //             }
    //             else {
    //                 $users = User::where('type', 1)->get();
    //                 if (count($users) <= 150) {
    //                     $addPayment = Payment::create([
    //                         'user_id' => $user['id'],
    //                         'first_name' => 'freebie',
    //                         'last_name' => 'freebie',
    //                         'paied' => 1,
    //                         'amount' => 0,
    //                         'paied_date' => date("Y-m-d"),
    //                         'for_months' => 12,
    //                         'till' => date('Y-m-d', strtotime("+12 months", strtotime(date("Y-m-d")))),
    //                         'tx_ref' => "freebie"
    //                     ]);;
    //                 }
    //             }

    //             return response()->json([
    //                 'status' => 'success',
    //                 'message' => 'User created successfully',
    //                 'user' => $user,
    //                 'has_paied' => $has_paied,
    //             ]);
    //         } else {
    //             //return error
    //             $response['error'] = 'Internal Server Error';
    //             $response['message'] = 'Internal server error. Please try again.';
    //             $statusCode = 500;
    //             return response()->json($response, $statusCode);
    //         }
    //     }else {
    //         $response['error'] = 'No Data';
    //         $response['message'] = 'No user found for this phone number.';
    //         $statusCode = 400;
    //         return response()->json($response, $statusCode);
    //     }
    // }

    // public function verifyOTPRegister(Request $request) 
    // {
    //     date_default_timezone_set('Africa/Addis_Ababa');
    //     $input = $request->all();

    //     $validator = Validator::make($input, [
    //         'phone'     => 'required|exists:users,phone',
    //         'otp'       => 'required',
    //     ]);
        
    //     if($validator->fails()){
    //         return $this->sendError('Validation Error.', $validator->errors());       
    //     }

    //     //check for otp validity and then generate accesstoken
    //     $user = User::where('phone', $input['phone'])->first();
    //     if ($user) {
    //         $otp = OTP::where('otp', $input['otp'])->where('user_id', $user->id)->first();
            
    //         $datetime   = date("Y-m-d H:i:s");
    //         $now        = strtotime($datetime);
            
    //         if ($otp && $otp->used_for == 2 && (strtotime($otp->expires_at) > $now)) {
    //             if ($input['otp'] === $otp->otp) {
    //                 $token = auth()->login($user);

    //                 if ($token) {
    //                     $user->phone_verified_at = $datetime;
    //                     $user->save();

    //                     if ($user) {

    //                         $user = User::where('phone', $input['phone'])->first();

    //                         if ($user->type == 1) {
    //                             $user->assignRole('cast');
    //                         } else if ($user->type == 2) {
    //                             $user->assignRole('director');
    //                         } else if ($user->type == 3) {
    //                             $user->assignRole('crew');
    //                         }

    //                         if ($user->type == '1') {
    //                             //castee
    //                             $has_paied = false;
    //                         } else if ($user->type == '2') {
    //                             //director
    //                             $has_paied = true;
    //                         } else if ($user->type == '0') {
    //                             //admin
    //                             $has_paied = false;
    //                         }

    //                         $payment = Payment::where('user_id', $user->id)->first();

    //                         if (!is_null($payment) && $payment->paied == 1) {
    //                             //check for expiration
    //                             $datetime   = date("Y-m-d");
    //                             $now        = strtotime($datetime);
                                
    //                             if (strtotime($payment->till) > $now) {
    //                                 $has_paied = true;
    //                             }
    //                         }

    //                         return response()->json([
    //                             'status' => 'success',
    //                             'user' => $user,
    //                             'has_paied' => $has_paied,
    //                             'permissions' => $user->getPermissionsViaRoles(),
    //                             'authorisation' => [
    //                                 'token' => $token,
    //                                 'type' => 'bearer',
    //                             ]
    //                         ]);
    //                     } else {
    //                         return response()->json([
    //                             'status' => 'error',
    //                             'message' => 'Unauthorized',
    //                         ], 401);
    //                     }
    //                 } else {
    //                     return response()->json([
    //                         'status' => 'error',
    //                         'message' => 'Unauthorized',
    //                     ], 401);
    //                 }
    //             }
    //         } else {
    //             return response()->json([
    //                 'status' => 'error',
    //                 'message' => 'Unauthorized',
    //             ], 401);
    //         }
    //     } else {
    //         return response()->json([
    //             'status' => 'error',
    //             'message' => 'Unauthorized',
    //         ], 401);
    //     }
    // }

    // public function resendOTP(Request $request) 
    // {
    //     $validator = Validator::make($request->all(), [
    //         'phone' => 'required|string|exists:users,phone'
    //     ]);

    //     if($validator->fails()){
    //         return $this->sendError('Validation Error.', $validator->errors());       
    //     }

    //     $input = $request->all();

    //     $user = User::where('phone', $input['phone'])->first();

    //     if ($user && $user->phone_verified_at == "") {
    //         $otp = $this->generatePIN();
    //         //check the database for otp not to send an already sent otp
    //         //delete all otp for the user

    //         date_default_timezone_set('Africa/Addis_Ababa');

    //         $datetime = date("Y-m-d H:i:s");
    //         $endTime = strtotime("+5 minutes", strtotime($datetime));

    //         $otp_data = [
    //             'user_id'           => $user->id,
    //             'otp'               => $otp,        
    //             'used_for'          => 2,
    //             'expires_at'        => date("Y-m-d H:i:s", $endTime),
    //         ];
            
    //         $created = OTP::create($otp_data);

    //         if ($created) {
    //             //send the otp via SMS
    //             $to = $input['phone'];
    //             $message = $otp;
    //             $template_id = 'otp';
                
    //             try{
    //                 $send = $this->sendSMS($to, $message, $template_id);
    //             } catch (Exception $e)
    //             {
    //                 return $e;
    //             }
    //             //return success
    //             return response()->json([
    //                 'status' => 'success',
    //                 'message' => 'OTP sent successfully',
    //                 'user' => $user
    //             ]);
    //         } else {
    //             //return error
    //             $response['error'] = 'Internal Server Error';
    //             $response['message'] = 'Internal server error. Please try again.';
    //             $statusCode = 500;
    //             return response()->json($response, $statusCode);
    //         }
    //     }else {
    //         $response['error'] = 'No Data';
    //         $response['message'] = 'No user found for this phone number.';
    //         $statusCode = 400;
    //         return response()->json($response, $statusCode);
    //     }
    // }

    public function logout()
    {
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

    public function forgetPassword(Request $request)
    {
        $input = $request->all();

        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email',
        ]);
   
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());      
        }

        $token = Str::random(64);

        DB::table('password_resets')->insert(
            ['email' => $request->email, 'token' => $token, 'created_at' => Carbon::now()]
        );

        try {
            Mail::send('emails.forgetPassword', ['token' => $token], function($message) use($request){
                $message->to($request->email);
                $message->subject('Reset Password Notification');
            });
        } catch (Exeption $e)
        {}
    
        return $this->sendResponse([], 'Password reset mail sent successfully.');
    }
    
    public function resetPassword(Request $request)
    {
        $request->validate([
            'email'                     => 'required|email|exists:users',
            'token'                     => 'required|string|min:6',
            'password'                  => 'required|string|min:6|confirmed',
            'password_confirmation'     => 'required',
        ]);

        $updatePassword = DB::table('password_resets')->where(['email' => $request->email, 'token' => $request->token])->first();

        if(!$updatePassword) {
            $response['error'] = 'Invalid Request';
            $response['message'] = 'This request to reset password is invalid.';
            $statusCode = 400;
            return response()->json($response, $statusCode);
        }

        $user = User::where('email', $request->email)
                ->update(['password' => Hash::make($request->password)]);

        DB::table('password_resets')->where(['email'=> $request->email])->delete();

        return $this->sendResponse([], 'Password Reset Successfully.');
    }

    public function verifyEmail($token) 
    {
        try {
            $decrypted = Crypt::decryptString($token);
            
            $token = explode('~', $decrypted);

            $datetime   = date("Y-m-d H:i:s");
            $now        = strtotime($datetime);

            $user = User::where('email', $token[0])->first();

            if (strtotime($token[2]) > $now && $user->email_verified_at == "") {
                $user->email_verified_at = date('Y-m-d H:i:s');
                $user->save();
                
                // return response()->json([
                //     'status' => 'success',
                //     'message' => 'Email verified successfully.'
                // ]);
                return redirect()->away('https://google.com');
            } else {
                // $response['error'] = 'Request Error';
                // $response['message'] = 'Your request is invalid. please request a verification email again.';
                // $statusCode = 400;
                // return response()->json($response, $statusCode);
                return redirect()->away('https://google.com');
            }
        } catch (DecryptException $e) {
            //
            $response['error'] = 'Internal Server Error';
            $response['message'] = 'Internal server error. Please try again.';
            $statusCode = 500;
            return response()->json($response, $statusCode);
        }
    }

    // public function generatePIN($digits = 4)
    // {
    //     $i = 0; //counter
    //     $pin = ""; //our default pin is blank.
    //     while($i < $digits){
    //         //generate a random number between 0 and 9.
    //         $pin .= mt_rand(0, 9);
    //         $i++;
    //     }
    //     return $pin;
    // }

    // private function sendSMS($to, $message, $template_id)
    // {    
    //     $postData = array('to' => $to, 'message' => $message,  'template_id' =>$template_id,  'password' => env('SMS_PASSWORD'), 'username' => env('SMS_USERNAME'));// 'token' => env('SMS_TOKEN'));
        
    //     $url = env('SMS_SERVER') . "/send";    
    //     $content = json_encode($postData);
        
    //     $curl = curl_init($url);
    //     curl_setopt($curl, CURLOPT_HEADER, false);
    //     curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    //     curl_setopt($curl, CURLOPT_HTTPHEADER,
    //             array("Content-type: application/json"));
    //     curl_setopt($curl, CURLOPT_POST, true);
    //     curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
    //     $json_response = curl_exec($curl);
    //     $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    //     curl_close($curl);
        
    //     return $json_response; 
    // }
}