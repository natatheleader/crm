<?php

namespace App\Http\Controllers\Api;

use App\Models\AgentProfile;
use Illuminate\Http\Request;

class AgentProfileController extends BaseController
{
    // public function __construct()
    // {
        // $this->middleware('auth:api');
        // $this->middleware('permission:read address|read profile', ['only' => ['index', 'show']]);
        // $this->middleware('permission:create address|create profile', ['only' => ['store']]);
        // $this->middleware('permission:edit address|edit profile', ['only' => ['update']]);
        // $this->middleware('permission:delete address|delete profile', ['only' => ['destroy']]);
    // }

    public function index()
    {        
        $address = Address::paginate();

        return $this->sendResponse($address, 'Agent Profile retrieved successfully.');
    }

    public function store(Request $request)
    {
        $input = $request->all();

        $input['profile_id'] = Auth::user()->profile->id;
   
        $validator = Validator::make($input, [
            'profile_id'            => 'required|exists:profiles,id|unique:addresses,profile_id',
            'phone_1'               => 'required',
            'nationality'           => 'required',
            'country'               => 'required'
        ]);
   
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }

        $address = Address::create($input);

        return $this->sendResponse(new AddressResource($address), 'Address created successfully.');
    }

    public function show(AgentProfile $agentProfile)
    {
    }

    public function update(Request $request, AgentProfile $agentProfile)
    {
    }

    public function destroy(AgentProfile $agentProfile)
    {
    }
}
