import os
import subprocess
import threading
import time
import sys

def run_subprocess(command, working_dir='.', env=None, expected_returncode=0, timeout=2):
    """
    Helper function to run a shell command and report success/failure
    depending on the exit status of the shell command.
    """
    if env is not None:
        env_ = os.environ.copy()
        env_.update(env)
        env = env_

    # Note we need to capture stdout/stderr from the subprocess,
    # then print it, which nose/unittest will then capture and
    # buffer appropriately
    print(working_dir + " > " + " ".join(command))
    
    proc = subprocess.Popen(
        ["/bin/bash"],
        stdin = subprocess.PIPE,
        stdout = subprocess.PIPE,
        stderr = subprocess.STDOUT,
        cwd = working_dir,
        env = env,
    )

    recorded_stdout = ""

    def output_capture_function():
        nonlocal recorded_stdout
        while proc.poll() is None:
            nextline = proc.stdout.readline()
            recorded_stdout += nextline.decode('ascii')

    output_capture = threading.Thread(target=output_capture_function)
    output_capture.start()

    def run_function(command):
        cmd = command.encode('ascii') + b"\nexit\n"
        return proc.communicate(input = cmd)

    run_thread = threading.Thread(target=run_function, kwargs={"command": " ".join(command)})
    run_thread.daemon = True
    run_thread.start()
    run_thread.join(timeout)
    
    if run_thread.is_alive():
        print(recorded_stdout)
        os.killpg(proc.pid, 15)
        assert False, "Process hung"
    else:
        print(recorded_stdout)
        assert proc.returncode == expected_returncode, \
            "Got unexpected return code {}".format(proc.returncode)
        return recorded_stdout
