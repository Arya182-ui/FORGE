def evaluate_expression(user_input: str):
    # Vulnerable eval call
    result = eval(user_input)
    return result

def run_dynamic_code(python_code: str):
    # Vulnerable exec call
    exec(python_code)
