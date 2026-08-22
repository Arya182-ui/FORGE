import pickle
import yaml

def load_user_object(raw_bytes: bytes):
    # Vulnerable pickle loads
    return pickle.loads(raw_bytes)

def load_configuration(yaml_text: str):
    # Vulnerable yaml load without SafeLoader
    return yaml.load(yaml_text)
