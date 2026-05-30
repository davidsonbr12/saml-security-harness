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
];
