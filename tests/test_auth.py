from fast_zero.security import create_access_token


def test_get_token(client, user):
    response = client.post(
        '/token',
        data={'username': user.email, 'password': user.clean_password},
    )
    token = response.json()

    assert response.status_code == 200
    assert 'access_token' in token
    assert 'token_type' in token


def test_get_token_user_not_exists(client):
    response = client.post(
        '/token',
        data={'username': 'felipe', 'password': 'senhaErrada'},
    )

    assert response.status_code == 400
    assert response.json() == {'detail': 'Incorrect email or password'}


def test_get_token_wrong_password(client, user):
    response = client.post(
        '/token',
        data={'username': user.email, 'password': 'senhaErrada'},
    )

    assert response.status_code == 400
    assert response.json() == {'detail': 'Incorrect email or password'}


def test_use_token_user_not_exists(client):
    access_token = create_access_token(data={'sub': 'meuemail@email.com'})

    response = client.put(
        '/users/1',
        headers={'Authorization': f'Bearer {access_token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_use_invalid_token(client):
    access_token = create_access_token(data={})

    response = client.put(
        '/users/1',
        headers={'Authorization': f'Bearer {access_token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_dont_send_token(client):
    response = client.put(
        '/users/1',
        headers={'Authorization': 'Bearer '},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == 401
    assert response.json() == {'detail': 'Could not validate credentials'}
