class JWTException(Exception):
    pass


class NotFoundSecret(JWTException):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class NotFountAlgorithm(JWTException):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


# FastException.HTTP_409_CONFLICT  bearer
class InvalidBearer(JWTException):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
