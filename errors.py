class ExitCode:
    # Standard exit codes for the bchoc program.
    OK = 0          # success
    E_GENERAL = 1    # general error
    E_ARGS = 2      # invalid arguments
    E_AUTH = 3      # authentication / authorization failure
    E_STATE = 4     # invalid blockchain state / operation
    E_IO = 5        # file I/O error
    E_VERIFY = 6    # verification / integrity error


class BchocError(Exception):
    # Custom exception carrying an exit code and message.
    def __init__(self, code: int, msg: str) -> None:
        super().__init__(msg)
        self.code = code
        self.msg = msg

    def __str__(self) -> str:
        # Return a readable representation of the error.
        return f"[{self.code}] {self.msg}"