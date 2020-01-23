# VT-IDA Plugin
This is the official VirusTotal plugin for Hex-Rays IDA Pro. This plugin integrates functionality from VirusTotal web services into the IDA Pro's user interface. 

The current version is v0.7beta, This plugin is not production-ready yet, and unexpected behavior can still occur. This release integrates VTGrep into IDA Pro, facilitating the searching for similar code, strings, or just a sequence of bytes.

## Requirements
This plugin has been developed for **IDA Pro 7.0** and beyond, currently using Python 2.7 API. Next releases will be compatible with Python 3.x

This plugin requires the "requests" module, the easiest way of installing it is by using ``pip``:

```bash
$ pip install requests
```

## Installation
Copy the content of the ``plugin`` directory into the IDA Pro's plugin directory. 

| OS      | Plugin path                                 |
| ------- | ------------------------------------------- |
| Linux   | `/opt/ida-7.X/plugins`                      |
| macOS   | `~/.idapro/plugins`                         |
| Windows | `%ProgramFiles%\IDA 7.X\plugins`       |

Edit the `vt_ida/config.py` file and enter your private API Key, then start IDA Pro.


## Usage
While in the disassembly window, select an area of instructions and right-click to chose one of the following searching methods:

* Search for bytes: search for the same bytes of the area selected
* Search for similar code: identify memory offsets or addresses in the current area selected and wildcard them
* Search for similar code (strict): wildcard all the constants defined in the current area 
* Search for similar functions: identify the current function and search for a similar one (wildcarding offsets and memory addresses)

The current version only supports **Intel 32/64 bits** when searching for similar code (or functions). Support for more processors will be added in the future. 

Another option is to look for similar strings. To search for similar ones, open the `Strings Windows` in IDA Pro, right-click on any string and select `Virus Total -> Search for string`. 

These actions will launch a new instance of your default web browser, pointing to the result of the query sent to VTGrep. Remember that your default web browser must be logged into your VirusTotal Enterprise account in order to see the results.


Check IDA Pro's output window for any message that may need your attention.


