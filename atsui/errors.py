class ApiError(Exception):
    name = "api_error"
    details = "Something wrong happened with the data you send to the API."
    status_code = 400
    data = False
    def __init__(self, *message):
        Exception.__init__(self)

    def to_dict(self):
        if self.data:
            return {
                "name": self.name,
                "details": self.details,
                "data": self.data,
                "status_code": self.status_code,
            }
        else:
            return {
                "name": self.name,
                "details": self.details,
                "status_code": self.status_code,
            }

class DataRequired(ApiError):
    name = "data_required"
    details = "This route requires more information to function."

class DataInvalid(ApiError):
    name = "data_invalid"
    details = "The data supplied for this request was invalid."

class LoginRequired(ApiError):
    name = "login_required"
    details = "The resource requested requires authentication."
    status_code = 403

class LoginInvalid(ApiError):
    name = "login_invalid"
    details = "The username and password did not match."
    status_code = 401

class UsernameTaken(ApiError):
    name = "username_taken"
    details = "The username has been taken."

class UserNotFound(ApiError):
    name = "user_not_found"
    details = "The specified user could not be found."

class PasswordIncorrect(ApiError):
    name = "password_incorrect",
    details = "Password given was incorrect."
