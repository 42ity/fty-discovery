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
