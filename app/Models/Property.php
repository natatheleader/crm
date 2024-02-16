<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;

use Illuminate\Database\Eloquent\Model;

class Property extends Model
{
    use HasFactory;

    protected $fillable = [
        'property_id',
        'country',
        'state',
        'city',
        'subcity',
        'woreda',
        'street',
        'address',
        'type',
        'bedrooms',
        'bathrooms',
        'floors',
        'gross_area',
        'net_area',
        'completion_percent',
        'description',
        'furnished',
        'status',
    ];

    public $guarded = [];
}
