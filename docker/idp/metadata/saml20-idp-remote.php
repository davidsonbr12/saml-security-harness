<?php
// IdP metadata as seen by the SP module running in the same container.
// The cert filename is relative to SSP's certdir (cert/).
$metadata['__DYNAMIC:1__'] = [
    'SingleSignOnService' => [
        [
            'Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8080/simplesaml/module.php/saml/idp/singleSignOnService',
        ],
    ],
    'certificate' => 'idp.crt',
];
