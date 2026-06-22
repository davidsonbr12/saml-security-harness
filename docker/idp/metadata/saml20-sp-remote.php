<?php
$metadata['http://localhost:8080/sp'] = [
    'AssertionConsumerService' => [
        [
            'Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'http://localhost:8080/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8080/sp/slo',
        ],
    ],
];
