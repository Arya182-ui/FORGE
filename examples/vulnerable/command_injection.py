import os
import subprocess

def ping_host(host_address: str):
    # Vulnerable os.system call
    os.system("ping -c 1 " + host_address)

def execute_user_script(script_path: str):
    # Vulnerable subprocess call with shell=True
    subprocess.run(f"python {script_path}", shell=True)
