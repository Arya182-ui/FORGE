def run_user_code(user_code: str):
    # Expected dangerous eval at line 3
    result = eval(user_code)
    return result
