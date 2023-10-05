from fast_zero.schemas import UserPublic
from fast_zero.security import create_access_token


def test_root_deve_retornar_200_e_ola_mundo(client):
    response = client.get('/')

    assert response.status_code == 200
    assert response.json() == {'message': 'Olá Mundo!'}


def test_create_user(client):
    response = client.post(
        '/users/',
        json={
            'username': 'aline',
            'email': 'aline@example.com',
            'password': 'secret',
        },
    )

    assert response.status_code == 201
    assert response.json() == {
        'username': 'aline',
        'email': 'aline@example.com',
        'id': 1,
    }


def test_create_user_with_same_username(client):
    client.post(
        '/users/',
        json={
            'username': 'aline',
            'email': 'aline@example.com',
            'password': 'secret',
        },
    )

    response = client.post(
        '/users/',
        json={
            'username': 'aline',
            'email': 'aline@example.com',
            'password': 'secret',
        },
    )

    assert response.status_code == 400
    assert response.json() == {'detail': 'Username already registered'}


def test_read_users(client):
    response = client.get('/users/')

    assert response.status_code == 200
    assert response.json() == {'users': []}


def test_read_users_with_users(client, user):
    user_schema = UserPublic.model_validate(user).model_dump()
    response = client.get('/users/')
    assert response.json() == {'users': [user_schema]}


def test_update_user(client, user, token):
    response = client.put(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        'username': 'bob',
        'email': 'bob@example.com',
        'id': 1,
    }


def test_update_user_unauthorized(client, token):
    response = client.put(
        '/users/2',
        headers={'Authorization': f'Bearer {token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == 400
    assert response.json() == {'detail': 'Not enough permissions'}


def test_delete_user(client, user, token):
    response = client.delete(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 200
    assert response.json() == {'detail': 'User deleted'}


def test_delete_user_unauthorized(client, token):
    response = client.delete(
        '/users/2',
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 400
    assert response.json() == {'detail': 'Not enough permissions'}


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
