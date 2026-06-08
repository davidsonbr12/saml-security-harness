from harness.client import saml_login

def test_valid_login_returns_200(idp_container):
    response = saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "user1",
        "password1"
    )
    assert response.status_code == 200
