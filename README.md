# Python PsExec Library

This library is run commands on a remote Windows host through SMB/RPC like the
PsExec tool does. It is very closely related to the
[smbprotocol](https://github.com/jborean93/smbprotocol) package.

This is still a work in progress but stay tuned.

## Requirements

Insert requirements here


## Host Requirements

For this to work SMB must be enabled and ...


## Example

Here is an example of how to run a command with this library

```
from pypsexec.client import Client

c = Client("username", "password", "server", encrypt=True)
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

    # run command asynchronously (in background)
    stdout, stderr, rc = c.run_executable("longrunning.exe",
                                          arguments="/s other args",
                                          async=True
finally:
    c.remove_service()
    c.disconnect()
```
