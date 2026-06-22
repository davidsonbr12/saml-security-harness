<?php
$config = [
    'admin' => [
        'core:AdminPassword',
    ],
    'example-userpass' => [
        'exampleauth:UserPass',
        'user1:password1' => [
            'uid' => ['user1'],
            'email' => ['user1@example.com'],
            'eduPersonAffiliation' => ['member'],
        ],
        'user2:password2' => [
            'uid' => ['user2'],
            'email' => ['user2@example.com'],
            'eduPersonAffiliation' => ['member'],
        ],
    ],

    'default-sp' => [
        'saml:SP',
        'entityID' => 'http://localhost:8080/sp',
        'idp' => '__DYNAMIC:1__',
    ],
];
