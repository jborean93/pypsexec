# Changelog

## 1.0.0 - TBD

* Breaking change where processes are run as the native architecture bitness, e.g. 64-bit on 64-bit OS' and 32-bit on 32-bit OS'
    * This changes the old behaviour of always running as a 32-bit process.
    * Any application relying on running with 32-bit paths will need to set `wow64=True` on `run_executable()` to restore the older behaviour.
* Breaking change, the `stdout`, stderr`, and `stdin` should be an byte IO stream like `BytesIO`
    * The `stdout` and `stderr` stream must support write operations to write the standard out and error when received by the server
    * The `stdin` stream must support read operations to read input data to send to the remote process' input stream.
    * When `stdout` or `stderr` is set, the return tuple will no longer contain the byte string output of the stream that was overriden.
* Dropped support for Python 2.6 and Python 3.4.
* Updated the `PAExec` executable to `1.27`.
* Added support for using the `with` statement with `Client` for more readable code.
* Set minumum version of smbprotocol to `1.0.0` to take advantage of new simpler library.


## 0.1.0 2018-03-07

Initial release of pypsexec.
