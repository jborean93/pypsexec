# Changelog

## 0.2.0 - 2020-12-14

* Breaking change where processes are run as the native architecture bitness, e.g. 64-bit on 64-bit OS' and 32-bit on 32-bit OS'
    * This changes the old behaviour of always running as a 32-bit process.
    * Any application relying on running with 32-bit paths will need to set `wow64=True` on `run_executable()` to restore the older behaviour.
* Dropped support for Python 2.6 and Python 3.4.
* Updated the `PAExec` executable to `1.27`.
* Handle non-ASCII characters when enumerating the services on the remote host.


## 0.1.0 2018-03-07

Initial release of pypsexec.
