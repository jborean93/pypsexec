# Changelog

## 0.4.0+welflo.2 - TBD

* Dropped old Python versions, new minimum is 3.10
* Generate a UUID-based PAExec service name for each Client instead of using the local PID and hostname, avoiding name reuse between clients while Windows is still deleting a previous service. Standard input/output pipe names are unchanged.

## 0.4.0+welflo.1 - 2026-11-03

* Dropped old Python versions, new minimum is 3.9
* Close and reset the service handle after deletion so an existing service can be recreated and started.
* Generate a UUID-based PAExec service name for each Client instead of using the local PID and hostname, avoiding name reuse between clients while Windows is still deleting a previous service. Standard input/output pipe names are unchanged.

## 0.3.0 - 2021-10-22

* Dropped Python 2.7 and 3.5, new minimum is 3.6
* Updated the `PAExec` executable to `1.29`


## 0.2.0 - 2020-12-14

* Breaking change where processes are run as the native architecture bitness, e.g. 64-bit on 64-bit OS' and 32-bit on 32-bit OS'
    * This changes the old behaviour of always running as a 32-bit process.
    * Any application relying on running with 32-bit paths will need to set `wow64=True` on `run_executable()` to restore the older behaviour.
* Dropped support for Python 2.6 and Python 3.4.
* Updated the `PAExec` executable to `1.27`.
* Handle non-ASCII characters when enumerating the services on the remote host.


## 0.1.0 2018-03-07

Initial release of pypsexec.
