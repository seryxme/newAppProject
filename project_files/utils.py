import bcrypt as bcrypt


def hash_password(password: str) -> str:
    password = password.encode()
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt).decode()


def validate_password(user_password: str, hashed_password: str) -> bool:
    user_password: bytes = user_password.encode()
    hashed_password: bytes = hashed_password.encode()
    return bcrypt.checkpw(user_password, hashed_password)


if __name__ == '__main__':
    pw = hash_password('mynewpassword123')
    print(pw)
    print(validate_password('mynewpassword12', pw))