from harness.client import saml_login

def test_valid_login_returns_200(idp_container):
    response = saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "user1",
        "password1"
    )
    assert response.status_code == 200

def test_uid_in_response(idp_container):
    response= saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "user1",
        "password1"
    )
    assert "user1" in response.text

def test_email_in_response(idp_container):
    response= saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "user1",
        "password1"
    )
    assert "user1@example.com" in response.text

def test_affiliation_in_response(idp_container):
    response= saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "user1",
        "password1"
    )
    assert "member" in response.text

def test_wrong_password_rejected(idp_container):
    response= saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "bad_user",
        "bad_password"
    )
    assert "user1@example.com" not in response.text

def test_wrong_username_rejected(idp_container):
    response= saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "bad_user1",
        "bad_password"
    )
    assert "user1@example.com" not in response.text

def test_user2_login_returns_200(idp_container):
    response= saml_login(
        "http://localhost:8080/simplesaml/module.php/admin/test/example-userpass",
        "user2",
        "password2"
    )
    assert response.status_code == 200
