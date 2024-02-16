<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('properties', function (Blueprint $table) {
            $table->id();
            $table->string('property_id');
            $table->string('country');
            $table->string('state');
            $table->string('city');
            $table->string('subcity');
            $table->string('woreda');
            $table->string('street');
            $table->string('address');
            $table->int('type');
            $table->int('bedrooms');
            $table->string('bathrooms');
            $table->string('floors');
            $table->double('gross_area');
            $table->double('net_area');
            $table->double('completion_percent');
            $table->text('description');
            $table->double('furnished');
            $table->int('status');
            //agent profile, media
            $table->timestamps();
        });
    }
};
