<?php

namespace App\Http\Controllers\Api;

use App\Models\Property;
use Illuminate\Http\Request;

class PropertyController extends BaseController
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
        $property = Property::paginate();

        return $this->sendResponse($property, 'Properties retrieved successfully.');  
    }

    public function store(Request $request)
    {
        $input = $request->all();

        // $input['profile_id'] = Auth::user()->profile->id;
   
        $validator = Validator::make($input, [
            'property_id'               => 'required|unique:properties,property_id',
            'country'                   => 'required',
            'state'                     => 'required',
            'city'                      => 'required',
            'subcity'                   => 'required',
            'woreda'                    => 'required',
            'street'                    => 'required',
            'address'                   => 'required',
            'type'                      => 'required',
            'bedrooms'                  => 'required|numeric',
            'bathrooms'                 => 'required|numeric',
            'floors'                    => 'required|numeric',
            'gross_area'                => 'required|numeric',
            'net_area'                  => 'required|numeric',
            'completion_percent'        => 'required|numeric',
            'description'               => 'required',
            'furnished'                 => 'required|numeric',
            'status'                    => 'required',
        ]);
   
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }

        $property = Property::create($input);

        return $this->sendResponse(new PropertyResource($property), 'Property created successfully.');
    }

    public function show(Property $property)
    {
        $property = Property::find($id);

        if (is_null($property)) {
            return $this->sendError('Property not found.');
        } 

        return $this->sendResponse(new PropertyResource($property), 'Property retrieved successfully.');
    }

    public function update(Request $request, Property $property)
    {
        $input = $request->all();

        // $property_id = Auth::user()->profile->id;
   
        $property = Property::find($id);

        $validator = Validator::make($input, [
            'property_id'               => 'required|unique:properties,property_id',
            'country'                   => 'required',
            'state'                     => 'required',
            'city'                      => 'required',
            'subcity'                   => 'required',
            'woreda'                    => 'required',
            'street'                    => 'required',
            'address'                   => 'required',
            'type'                      => 'required',
            'bedrooms'                  => 'required|numeric',
            'bathrooms'                 => 'required|numeric',
            'floors'                    => 'required|numeric',
            'gross_area'                => 'required|numeric',
            'net_area'                  => 'required|numeric',
            'completion_percent'        => 'required|numeric',
            'description'               => 'required',
            'furnished'                 => 'required|numeric',
            'status'                    => 'required',
        ]);
   
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }

        $property->property_id = $input['property_id'];
        $property->country = $input['country'];
        $property->state = $input['state'];
        $property->city = $input['city'];
        $property->subcity = $input['subcity'];
        $property->woreda = $input['woreda'];
        $property->street = $input['street'];
        $property->address = $input['address'];
        $property->type = $input['type'];
        $property->bedrooms = $input['bedrooms'];
        $property->floors = $input['floors'];
        $property->gross_area = $input['gross_area'];
        $property->net_area = $input['net_area'];
        $property->completion_percent = $input['completion_percent'];
        $property->description = $input['description'];
        $property->furnished = $input['furnished'];
        $property->status = $input['status'];
        $property->save();
   
        return $this->sendResponse(new PropertyResource($property), 'Property updated successfully.');
    }

    public function destroy(Property $property)
    {
        $property = Property::find($id);

        $property->delete();

        return $this->sendResponse([], 'Property deleted successfully.');
    }
}
