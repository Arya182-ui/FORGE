import subprocess

def ping_host_secure(host_address: str):
    # Secure subprocess invocation passing argument array with shell=False
    subprocess.run(["ping", "-c", "1", host_address], shell=False, check=True)
