import os
import ast
import yaml

# Safe retrieval from environment variables
SECRET_KEY = os.environ.get("SECRET_KEY", "")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")

def parse_dict_safely(raw_str: str):
    # Safe ast.literal_eval
    return ast.literal_eval(raw_str)

def load_yaml_safely(yaml_str: str):
    # Safe PyYAML loading
    return yaml.safe_load(yaml_str)
