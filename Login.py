import Database  # Introduction of database module


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def authenticate(self, password):

        return self.password == password


def register_user(username, password):

    if Database.check_user_exists(username):  # Use the database to check whether the user exists
        print("The user name already exists. Please select another user name")
        return False

    if Database.add_user(username, password):  # Add a user to the database
        print(f"user {username} registered successfully！")
        return True
    else:
        print("Registration failed, please try again.")
        return False


def login_user(username, password):

    if Database.verify_user(username, password):
        print(f"welcome back，{username}！")
        return True
    else:
        print("The user name or password is incorrect. Please try again.")
        return False


def check_user_exists(username):

    return Database.check_user_exists(username)
