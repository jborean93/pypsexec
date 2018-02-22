# Python PsExec Library

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/pypsexec/blob/master/LICENSE)
[![Travis Build](https://travis-ci.org/jborean93/pypsexec.svg)](https://travis-ci.org/jborean93/pypsexec)
[![AppVeyor Build](https://ci.appveyor.com/api/projects/status/github/jborean93/pypsexec?svg=true)](https://ci.appveyor.com/project/jborean93/pypsexec)
[![Coverage](https://coveralls.io/repos/jborean93/pypsexec/badge.svg)](https://coveralls.io/r/jborean93/pypsexec)

This library can run commands on a remote Windows host through Python. This
means that it can be run on any host with Python and does not require any
binaries to be present or a specific OS. It uses SMB/RPC to executable commands
in a similar fashion to the popular PsExec tool.

The executable wrapper that is sent to the service is based on the
[PAExec](https://github.com/poweradminllc/PAExec) library. PAExec is an free,
redistributable and open source equivalent to Microsoft's
[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
application. This program is stored as a binary in this package and is used
to run the remote service and start the process execution.

I would like to thank the developers of Power Admin for creating this library
as it has made this library a lot less complex than what it would have been.


## Features

With pypsexec you can run commands of a remote Windows host like you would with
psexec. This tools can configuration this process with the following features;

* Run as a specific local or domain user or the user
* Run as the local SYSTEM account
* Run as an interactive process
* Specify the session the interactive process should run on
* Specify the run level, `highest` or `limited`
* Set the priority of the process
* Set a timeout for the remote process
* Send input through the stdin pipe to the running process
* Set the processors the process can run on


## Further Info

These are the steps the library completes to work;

* Create an SMB connection to the host
* Copies across the PAExec binary to the `ADMIN$` share of the remote host
* Binds the Windows Service Manager to the opened `IPC$` tree using RPC
* Creates and starts a Windows service as the `SYSTEM` accound to run the bianry copied
* Connect to the PAExec named pipe the service runs
* Sends the process details to the PAExec service through the pipe
* Send a request to the PAExec service to start the process based on the settings sent
* Connect to the newly spawned process's stdout, stderr, stdin pipe (if not interactive or async)
* Read the stdout/stderr pipe until the process is complete
* Get the return code of the new process
* Stop and remove the PAExec service
* Remove the PAExec binary from the `ADMIN$` share

In the case of a failed process, the PAExec service and binary may not be
removed from the host and may need to be done manually. This is only the case
for a critical error or the cleanup functions not being called.

By default the data being sent to and from the server is encrypted to stop
people listening in on the network from snooping your data but this is only
supported for Server 2012 or Windows 8 onwards. Older hosts like Windows 7
or Server 2008 R2 will still work but without encryption. There is nothing
that can be done about thi as the encryption is based on the underlying
SMB transport and these older hosts don't support SMB encryption.

To disable encryption, set `encrypt=False` when initialising the `Client`
class. Unfortunately PAExec does not encrypt the data sent across the
network so command lines, credentials would be sent in plain text if SMB
encryption is not used. While the data is not encrypted, it does a simple
XOR scramble of the settings data but it is not as good as SMB encryption.

## Requirements

* Python 2.7, 2.7, 3.4-3.6
* [smbprotocol](https://github.com/jborean93/smbprotocol)

To install pypsexec, simply run

`pip install pypsexec`

This will download the required packages that are required and get your
Python environment ready to do.

Out of the box, pypsexec supports authenticating to a Windows host with NTLM
authentication but users in a domain environment can take advantage of Kerberos
authentication as well for added security. Currently the Windows implementation
of the smbprotocol does not support Kerberos auth but for other platforms you
can add support by running

```
# for Debian/Ubuntu/etc:
sudo apt-get install gcc python-dev libkrb5-dev
pip install smbprotocol[kerberos]

# for RHEL/CentOS/etc:
sudo yum install gcc python-devel krb5-devel krb5-workstation python-devel
pip install smbprotocol[kerberos]
```

From there to check that everything was installed correctly and the correct
GSSAPI extensions are available on that host, run

```
try:
    from gssapi.raw import inquire_sec_context_by_oid
    print("python-gssapi extension is available")
except ImportError as exc:
    print("python-gssapi extension is not available: %s" % str(exc))
```

If it isn't available, then either a newer version of the system's gssapi
implementation needs to be setup and python-gssapi compiled against that newer
version.


## Remote Host Requirements

The goal of this package to be able to run executables on a vanilla remote
Windows host without any customisations. Saying that, some of the protocols
used can be modified or disabled and would stop the package from working. What
pypsexec requires is;

* SMB to be up and running on the Windows port and readable from the Python host
* The `ADMIN$` share to be enabled with read/write access of the user configured
* The above usually means the configured user is an administrator of the Windows host
* At least SMB 2 on the host (Server 2008 and newer)


## Examples

Here is an example of how to run a command with this library

```
from pypsexec.client import Client

# creates an encrypted connection to the host with the username and password
c = Client("server", username="username", password="password")

# set encrypt=False for Windows 7, Server 2008
c = Client("server", username="username", password="password")

# if Kerberos is available, this will use the default credentials in the
# credential cache
c = Client("server")

# you can also tell it to use a specific Kerberos principal in the cache
# without a password
c = Client("server", username="username@DOMAIN.LOCAL")

c.connect()
try:
    c.create_service()

    # After creating the service, you can run multiple exe's without
    # reconnecting

    # run a simple cmd.exe program with arguments
    stdout, stderr, rc = c.run_executable("cmd.exe",
                                          arguments="/c echo Hello World")

    # run whoami.exe as the SYSTEM account
    stdout, stderr, rc = c.run_executable("whoami.exe", use_system_account=True)

    # run command asynchronously (in background), the rc is the PID of the spawned service
    stdout, stderr, rc = c.run_executable("longrunning.exe",
                                          arguments="/s other args",
                                          async=True)

    # run whoami.exe as a specific user
    stdout, stderr, rc = c.run_executable("whoami",
                                          arguments="/all",
                                          username="local-user",
                                          password="password",
                                          run_elevated=True)
finally:
    c.remove_service()
    c.disconnect()
```

In the case of a fatal failure, this project may leave behind some the PAExec
payload in `C:\Windows` or the service still installed. As these are uniquely
named they can build up over time. They can be manually removed but you can
also use pypsexec to cleanup them all up at once. To do this run

```
from pypsexec.client import Client

c = Client("server", username="username", password="password")
c.connect()
c.cleanup()  # this is where the magic happens
c.disconnect()
```

The script will delete any files that match `C:\Windows\PAExec-*` and any
services that match `PAExec-*`. For an individual run, the `remove_service()`
function should still be used.


### Run Executable Options

When calling `run_executable`, there are multiple kwargs that can define
how the remote process will work. These args are;

* `executable`: (string) The path to the executable to be run
* `arguments`: (string) Arguments for the executable
* `processors`: (list<int>) A list of processor numbers that the process can run on
* `async`: (bool) Doesn't wait until the process is complete before returning. The `rc` returned by the function is the `PID` of the async process, default is `False`
* `load_profile`: (bool) Load the user's profile, default is `True`
* `session_to_interact_with`: (int) The session ID to display the interactive process when `interactive=True`, default is `0`
* `interactive`: (bool) Runs the process as an interactive process. The stdout and stderr buffers will be `None` if `True`, default `False`
* `run_elevated`: (bool) When `username` is defined, will elevated permissions, default `False`
* `run_limited`: (bool) When `username` is defined, will run the process under limited permissions, default `False`
* `username`: (string) Used to run the process under a different user than the one that authenticated the SMB session
* `password`: (string) The password for `username`
* `use_system_account`: (bool) Run the process as `NT AUTHORITY\SYSTEM`
* `working_dir`: (string) The working directory of the process, default `C:\Windows\System32`
* `show_ui_on_win_logon`: (bool) Displays the UI on the Winlogon secure desktop when `use_system_account=True`, default `False`
* `priority`: (pypsexec.ProcessPriority) The priority level of the process, default `NORMAL_PRIORITY_CLASS`
* `remote_log_path`: (string) A path on the remote host to log the PAExec service details
* `timeout_seconds`: (int) The maximum time the process can run for, default is `0` (no timeout)
* `stdin`: (bytes) A byte string to send over the stdin pipe, does not work with `interactive=True` and `async=True`


## Logging

This library uses the builtin Python logging library and can be used to find
out what is happening in the pypsexec process. Log messages are logged to the
`pypsexec` named logger as well as `pypsexec.*` where `*` is each python script
in the `pypsexec` directory.

These logs are generally useful when debugging issues as they give you a more
step by step snapshot of what it is doing and what may be going wrong. The
debug level will also print out a human readable string of each SMB packet that
is sent out from the client but this level can get really verbose.


## Testing

To this module, you need to install some pre-requisites first. This can be done
by running;

```
pip install -r requirements-test.txt

# you can also run tox by installing tox
pip install tox
```

From there to run the basic tests run;

```
py.test -v --pep8 --cov pypsexec --cov-report term-missing

# or with tox 2.7, 2.7, 3.4, 3.5, and 3.6
tox
```

There are extra tests that only run when certain environment variables are set.
To run these tests set the following variables;

* `PYPSEXEC_SERVER`: The hostname or IP to a Windows host
* `PYPSEXEC_USERNAME`: The username to use authenticate with
* `PYPSEXEC_PASSWORD`: The password for `PYPSEXEC_USERNAME`

From there, you can just run `tox` or `py.test` with these environment
variables to run the integration tests.
