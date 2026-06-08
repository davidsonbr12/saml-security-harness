import pytest, requests, time, subprocess
@pytest.fixture(scope="session")
def idp_container():
    subprocess.run(["docker-compose", "up", "-d"], check=True)
    while True:
        try:
            requests.get("http://localhost:8080/simplesaml")
            break
        except:
            time.sleep(2)

    yield

    subprocess.run(["docker-compose", "down"], check=True)
