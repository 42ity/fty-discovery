# fty-discovery
it discovers NUT - Network UPS Tools supported devices, including power devices (ups, epdu, ats)
and cooling devices, over the network and publishes new device element in the asset DB.

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

If neither -a nor -r options are present, scan of all attached networks (localscan) will be performed.

#### from an installed base, using systemd, run:

```bash
systemctl start fty-discovery
```

## Protocols

### Mailbox requests

It is possible to request the agent discovery for:
* launch a scan based on the configuration;
* get the progression of the scan;
* stop a scan.

#### Launch the scan configured

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* LAUNCHSCAN/\<correlation_id>

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* <correlation_id>/OK
* <correlation_id>/ERROR
* <correlation_id>/RUNNING
* <correlation_id>/STOPPING

RUNNING reply means an other scan curently running.
STOPPING reply means an other scan is currently stopping.
ERROR reply can be occur if config file is missformed.

### Get the progression of the current scan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* PROGRESS/\<correlation_id>

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* <correlation_id>/OK/\'-1'
* <correlation_id>/OK/\<status>/\<percent>/\<nb of discovered devices>/\<nb of discovered ups>/\<nb of discovered epdu>/\<nb of discovered sts>
* <correlation_id>/ERROR

Where 
* 'status' is the current status of the scan. It can be '1' for "cancelled by user", '2' for "terminated" and '3' for "in progress" 
* 'percent' the percent number of the scan progression
* 'nb of discovered devices' is the number of all the discovered devices 
* each 'nb of discovered [...]' are the number of specific type of discovered device.

<correlation_id>/OK/\'-1' occur if no scan has been launched yet.


### Stop the current scan

The USER peer sends the following messages using MAILBOX SEND to fty-discovery peer:
* STOPSCAN

The fty-discovery peer MUST respond with one of the messages back to USER peer using MAILBOX SEND.
* OK
