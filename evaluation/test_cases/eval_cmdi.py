import os
import subprocess

def run_ping(ip: str):
    # Expected Command Injection at line 6
    os.system("ping " + ip)

def run_script(script: str):
    # Expected Command Injection at line 10
    subprocess.run(f"python {script}", shell=True)
