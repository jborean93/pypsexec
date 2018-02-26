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
PsExec. Current you can use pypsexec to do the following;

* Run as a specific local or domain user or the user
* Run as the local SYSTEM account
* Run as an interactive process
* Specify the session the interactive process should run on
* Specify the run level of the user token, `highest` or `limited`
* Set the priority of the process
* Set a timeout for the remote process
* Send input through the stdin pipe to the running process
* Set the processors the process can run on


## Further Info

While this info is not necessary for you to use this library it can help people
understand what is happening under the hood. This library runs the following
steps when running a command;

* Create an SMB connection to the host
* Copies across the PAExec binary to the `ADMIN$` share of the remote host
* Binds the Windows Service Manager to the opened `IPC$` tree using RPC
* Creates and starts a Windows service as the `SYSTEM` account to run the binary copied
* Connect to the PAExec named pipe the service creates
* Sends the process details to the PAExec service through the pipe
* Send a request to the PAExec service to start the process based on the settings sent
* Connect to the newly spawned process's stdout, stderr, stdin pipe (if not interactive or async)
* Read the stdout/stderr pipe until the process is complete
* Get the return code of the new process
* Stop and remove the PAExec service
* Remove the PAExec binary from the `ADMIN$` share
* Disconnects from the SMB connection

In the case of a failed process, the PAExec service and binary may not be
removed from the host and may need to be done manually. This is only the case
for a critical error or the cleanup functions not being called.

By default the data being sent to and from the server is encrypted to stop
people listening in on the network from snooping your data. Unfortunately this
uses SMB encryption which was added in the SMB 3.x dialects so hosts running
Windows 7, Server 2008, or Server 2008 R2 will not work with encryption.

This means that any data sent over the wire on these older versions of Windows
is viewable by anyone reading those packets. Any input or output of the process
comes through these packets so any secrets sent over the network won't be
encrypted. PAExec tries to reduce this risk by doing a simple XOR scramble of
the settings set in `run_executable` so it isn't plaintext but it can be
decoded by someone who knows the protocol.


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
can add support by installing the kerberos components of `smbprotocol`;

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
Windows host with as little setup as possible. Unfortunately there is still
some setup required to get working depending on the OS version and type
that is being used. What pypsexec requires on the host is;

* SMB to be up and running on the Windows port and readable from the Python host
* The `ADMIN$` share to be enabled with read/write access of the user configured
* The above usually means the configured user is an administrator of the Windows host
* At least SMB 2 on the host (Server 2008 and newer)

### Firewall Setup

By default, Windows blocks the SMB port 445 and it needs to be opened up before
pypsexec can connect to the host. To do this run either one of the following
commands;

```
# PowerShell (Windows 8 and Server 2012 or Newer)
Set-NetFirewallRule -Name FPS-SMB-In-TCP -Enabled True

# CMD (All OS's)
netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" dir=in new enable=Yes
```

This will open up inbound traffic to port `445` which is used by SMB.


### User Account Control

On the desktop variants of Windows (7, 8, 10), UAC is enabled by default and is
set to filter a network logon of a local account of their Administrative
rights. Unfortunately pypsexec requires these rights to both copy the
executable to the `ADMIN$` share as well as create the PAExec service on the
host. With the default setting it will receive an `ACCESS_IS_DENIED` response
when attempting either of the 2 as it's token does not have Administrative
rights.

To get it working on these OS', either configure UAC to not filter local
account tokens from a network logon or disable UAC entirely. Disabling UAC is
definitely an extreme step and should be avoided if possible but disabling
local token filtering means any network logons of an Administrator account
now gets the full rights of that user. To disable local token filter run the
following;

```
$reg_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$reg_prop_name = "LocalAccountTokenFilterPolicy"

$reg_key = Get-Item -Path $reg_path
$reg_prop = $reg_key.GetValue($reg_prop_name)
if ($null -ne $reg_prop) {
    Remove-ItemProperty -Path $reg_path -Name $reg_prop_name
}

New-ItemProperty -Path $reg_path -Name $reg_prop_name -Value 1 -PropertyType DWord
```

To disable UAC entirely, run the following;

```
$reg_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$reg_prop_name = "EnableLUA"

$reg_key = Get-Item -Path $reg_path
$reg_prop = $reg_key.GetValue($reg_prop_name)
if ($null -ne $reg_prop) {
    Remove-ItemProperty -Path $reg_path -Name $reg_prop_name
}

New-ItemProperty -Path $reg_path -Name $reg_prop_name -Value 0 -PropertyType DWord
```

After running either of these scripts, the Windows host needs to be rebooted
before the policies are enacted.


## Examples

Here is an example of how to run a command with this library

```
from pypsexec.client import Client

# creates an encrypted connection to the host with the username and password
c = Client("hostname", username="username", password="password")

# set encrypt=False for Windows 7, Server 2008
c = Client("hostname", username="username", password="password", encrypt=False)

# if Kerberos is available, this will use the default credentials in the
# credential cache
c = Client("hostname")

# you can also tell it to use a specific Kerberos principal in the cache
# without a password
c = Client("hostname", username="username@DOMAIN.LOCAL")

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
                                          asynchronous=True)

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

### Client Options

When creating the main pypsexec `Client` object there are some configuration
options that can be set to control the process. These args are;

* `server`: This needs to be set and is the host or IP address of the server to connect to
* `username`: The username to connect with. Can be `None` if `python-gssapi` is installed and a ticket has been granted in the local credential cache
* `password`: The password for `username`. Can be `None` if `python-gssapi` is installed and a ticket has been granted for the user specified
* `port`: Override the default port of `445` when connecting to the server
* `encrypt`: Whether to encrypt the messages or not, default is `True`. Server 2008, 2008 R2 and Windows 7 hosts do not support SMB Encryption and need this to be set to `False`


### Run Executable Options

When calling `run_executable`, there are multiple kwargs that can define
how the remote process will work. These args are;

* `executable`: (string) The path to the executable to be run
* `arguments`: (string) Arguments for the executable
* `processors`: (list<int>) A list of processor numbers that the process can run on
* `asynchronous`: (bool) Doesn't wait until the process is complete before returning. The `rc` returned by the function is the `PID` of the async process, default is `False`
* `load_profile`: (bool) Load the user's profile, default is `True`
* `interactive_session`: (int) The session ID to display the interactive process when `interactive=True`, default is `0`
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
* `stdout`: (pipe.OutputPipe) A class that implements pipe.OutputPipe that controls how the stdout output is processed and returned, will default to returning the byte string of the stdout. Is ignored when `interactive=True` and `asynchronous=True`
* `stderr`: (pipe.OutputPipe) A class that implements pipe.OutputPipe that controls how the stderr output is processed and returned, will default to returning the byte string of the stderr. Is ignored when `interactive=True` and `asynchronous=True`
* `stdin`: (bytes/generator) A byte string or generator that yields a byte string to send over the stdin pipe, does not work with `interactive=True` and `asynchronous=True`


## Logging

This library uses the builtin Python logging library and can be used to find
out what is happening in the pypsexec process. Log messages are logged to the
`pypsexec` named logger as well as `pypsexec.*` where `*` is each python script
in the `pypsexec` directory.

A way to enable the logging in your scripts through code is to add the
following to the top of the script being used;

```
import logging

logger = logging.getLogger("pypsexec")
logger.setLevel(logging.DEBUG)  # set to logging.INFO if you don't want DEBUG logs
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - '
                              '%(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
```

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


## Future

Some things I would be interested in looking at adding in the future would be

* Add a Python script that can be called to run adhoc commands like `PsExec.exe`
