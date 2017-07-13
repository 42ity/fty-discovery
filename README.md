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
* -r [subnet] to scan the subnet (192.168.1.0/24 format);
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
* launch a simple scan;
* launch a localscan (scan all of attached networks/subnetworks);
* launch a multiscan
* get the progression of the scan;
* stop a scan.

#### Launch a simple scan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* RUNSCAN/\<subnet>

where 
* '/' indicates a multipart string message
* 'subnet' is the subnetwork on wich the scan will be launch. It must be on the '192.168.1.0/24' format.

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

### Launch a multiscan

The USER sends the following messages using MAILBOX SEND to fty-discovery peer:
* MULTISCAN/\<nb_of_scan>/\<scan1>/\<scan2>/...

where
* '/' indicates a multipart string message
* 'nb_of_scan' is the number of scan who will have to be performed
* 'scanX' one of the scan to be performed. It can be on the '192.168.1.0/24' format in order to scan a network or ont the '192.168.1.12-192.168.1.18' format to scan a range.

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* OK
* ERROR
* RUNNING
* STOPPING

RUNNING reply  means an other scan curently running.
STOPPING reply means an other scan is in currently stopping.
ERROR can be reply if there is less 'scanX' than 'nb_of_scan' or if a 'scanX' is empty or misformed.

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
