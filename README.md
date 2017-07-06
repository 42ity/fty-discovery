# fty-discovery
it discovers power devices (ups, epdu, ats) over the network and publishes new device
element in the asset DB.

The default configuration values are in fty-discovery.cfg file (section default)

## How to build
To build fty-discovery project run:
```bash
./autogen.sh [clean]
./configure
make
make check # to run self-test
```
## How to run

To run fty-discovery project:
#### from within the source tree, run:
```bash
./src/fty-discovey
```
The available options are:
* -v for verbose mode;
* -r [range] to scan the range (192.168.1.0/24 format);
* -c [file] to define a config file;
* -a for agent mode.

If neither -a nor -r options are present, scan of all attached networks (localisation) will be performed.

#### from an installed base, using systemd, run:

```bash
systemctl start fty-discovery
```

## Protocols

### Mailbox requests

It is possible to request the agent discovery for:
* launch a range scan;
* launch a localscan (scan all of attached networks/subnetworks);
* get the progression of the scan;
* stop a scan.

#### Launch a range scan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* RUNSCAN/\<range>

where 
* '/' indicates a multipart string message
* 'range' is the range on wich the scan will be launch. It must be on the '192.168.1.0/24' format.

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* OK
* ERROR
* RUNNING
* STOPPING

RUNNING reply  means an other scan curently running.
STOPPING reply means an other scan is in currently stopping.
ERROR can be reply if range is empty or misformed.

### Launch a localscan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* LOCALSCAN

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* OK
* ERROR
* RUNNING
* STOPPING

RUNNING reply  means an other scan curently running.
STOPPING reply means an other scan is in currently stopping.

### Get the progression of the current scan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* PROGRESS

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* OK/\<percent>/\<nb of discovered devices>/\<nb of discovered ups>/\<nb of discovered epdu>/\<nb of discovered sts>
* ERROR

Where  
* 'percent' the percent number of the scan progression
* 'nb of discovered devices' is the number of all the discovered devices 
* each 'nb of discovered [...]' are the number of specific type of discovered device.


### Stop the current scan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* STOPSCAN

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* OK
