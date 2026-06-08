<?php
$config = [
    'baseurlpath' => 'http://localhost:8080/simplesaml/',
    'certdir' => 'cert/',
    'logging.handler' => 'errorlog',
    'datadir' => 'data/',
    'tempdir' => '/tmp/simplesaml',
    'session.cookie.secure' => false,

    'secretsalt' => 'testsalt1234567890abcdef12345678',
    'auth.adminpassword' => 'testpassword',

    'timezone' => 'America/New_York',

    'enable.saml20-idp' => true,
    'module.enable' => [
        'exampleauth' => true,
        'admin' => true,
        'saml' => true,
        'core' => true,
    ],

    'debug' => ['saml' => false],
    'showerrors' => true,
];
