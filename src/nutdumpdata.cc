/*  =========================================================================
    nutdumpdata - Wrapper around nut --dump-data tool

    Copyright (C) 2014 - 2017 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    nutdumpdata - Wrapper around nut --dump-data tool
@discuss
@end
*/

#include "fty_discovery_classes.h"
#include <iostream>
#include <fstream>

#define DEFAULT_DUMPDATA_LOOP 2
#define BIOS_NUT_DUMPDATA_ENV "BIOS_NUT_DUMPDATA"

static int dumpdata_loop=-1;
/**
 * \brief get number of driver loop to collect data
 * \return number of loop the driver will try to collect data (2 by default)
 *
 * Environment variables:
 * BIOS_NUT_DUMPDATA - could be used to set this parameter
 **/
static
int
s_get_nut_dumpdata_loop(){
    if (dumpdata_loop==-1){
        //ask system env
        if(::getenv (BIOS_NUT_DUMPDATA_ENV))
            dumpdata_loop=atoi(::getenv (BIOS_NUT_DUMPDATA_ENV));
    }
    //default value in any case
    if(dumpdata_loop<=0)
        dumpdata_loop=DEFAULT_DUMPDATA_LOOP;

    return dumpdata_loop;
}

/**
 * \brief set number of driver loop to collect data
 * \param[in] loop_nb - number of loop the driver will try to collect data (2 by default)
 *
 * Environment variables:
 * BIOS_NUT_DUMPDATA - could be used to set this paramter
 **/
void
set_nut_dumpdata_loop(unsigned int loop_nb){
    assert(loop_nb>0);
    dumpdata_loop=loop_nb;
}

/**
 * \brief one read line from istream
 */
static
ssize_t
s_readline(
        std::istream& inp,
        std::string& line)
{
    std::ostringstream buf;
    buf.clear();
    std::size_t ret;
    if (!inp.good() || inp.eof()) {
        return -1;
    }

    for (ret = 0; inp.good() && inp.peek() != '\n'; ret++) {
        char ch = static_cast<char>(inp.get());
        if (inp.eof())
            break;
        buf << ch;
    }
    if (inp.peek() == '\n') {
        buf << static_cast<char>(inp.get());
    }

    line.append(buf.str());
    return ret;
}

/**
 * \brief parse an output of nut-scanner
 *
 * \param inp  - input stream
 * \param out  - map of key/value string with output
 */
static
void
s_parse_nut_dumpdata_output(
    std::istream& inp,
    map_string_t& out)
{

    if (!inp.good() || inp.eof())
        return;

    std::stringstream buf;

    while (inp.good() && !inp.eof()) {
        std::string line;

        if (s_readline(inp, line) == -1)
            break;

        if (line.size() == 0)
            continue;

        //the expected format is key: value
        std::size_t pos=line.find(":");
        if(pos==std::string::npos)
            continue;
        //log_debug("'%s' : '%s'\n",line.substr(0,pos).c_str(),line.substr(pos+2,line.size()-pos-3).c_str());
        out[line.substr(0,pos)]=line.substr(pos+2,line.size()-pos-3);
    }
}

/**
 * \brief run nut --dump-data binary and return the output
 */
static
int
s_run_nut_dumpdata(
        const Argv& args,
        const int loop_nb,
        map_string_t& out)
{
    std::string o;
    std::string e;
    //we assumed that each loop could take up to 30 secondes
    zconfig_t *config = zconfig_load(getDiscoveryConfigFile().c_str());
    if (!config) {
        log_error("failed to load config file %s", getDiscoveryConfigFile().c_str());
        config = zconfig_new("root", NULL);
    }

    char* str_loop_time = zconfig_get(config, CFG_PARAM_DUMPDATA_LOOPTIME, DEFAULT_DUMPDATA_LOOPTIME);
    const size_t loop_time = std::stoi(str_loop_time);

    int timeout= loop_nb*loop_time;
    log_debug ("START: %s with timeout %d ...",args[0].c_str(),timeout);
    std::string debug_args;
    for(auto it: args){
        debug_args.append(it);
        debug_args.append(" ");
    }
    log_debug ("       %s",debug_args.c_str());
    int ret = output(args, o, e, timeout);
    log_debug ("       done with code %d", ret);

    zconfig_destroy(&config);
    if (ret != 0)
        return -1;

    std::istringstream inp{o};
    s_parse_nut_dumpdata_output(
            inp,
            out);

    if (out.empty())
        return -1;

    return 0;
}



/**
 * \brief generic entry point to get data from nut
 *
 * \param[in] driver  - name of the nut driver (dummy-ups, snmp-ups, netxml-ups ..)
 * \param[in] extra   - map of extra input arguments
 * \param[in] loop_nb - number of loop the driver will try to collect data
 * \param[out] out    - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata(
        const std::string& driver,
        const map_string_t& extra,
        const unsigned int loop_nb,
        map_string_t& out)
{
    Argv args;
    //to forge the command line to call the driver
    //first the driver name
    args.push_back(driver);
    //ask the driver to do dump-data
    args.push_back("-d");
    args.push_back(std::to_string(loop_nb));
    //set root as user to avoid any privildge issue
    args.push_back("-u");
    args.push_back("root");
    //set a unique name with the driver name
    args.push_back("-s");
    std::string name="dumpdata";
    name.append( std::to_string(rand() % 100000 + 1));
    args.push_back(name);
    //add all extra parameters
    for (auto it: extra) {
        args.push_back("-x");
        std::string option=it.first+"="+it.second;
        args.push_back(option);
    }
    return s_run_nut_dumpdata(
                args,
                loop_nb,
                out);

}


/**
 * \brief helper method to get data from a snmp-ups
 *
 * \param[in] port      - port (ip:port)
 * \param[in] community - community name. If empty, use "public"
 * \param[out] out      - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata_snmp_ups(
        const std::string& port,
        const std::string& community,
        map_string_t& out)
{
    map_string_t extra;
    extra["port"]=port;
    std::string comm;
    comm = community;
    if (comm.empty())
        comm = "public";
    extra["community"]=comm;
    int loop=s_get_nut_dumpdata_loop();
    return nut_dumpdata("/lib/nut/snmp-ups",
            extra,
            loop,
            out);
}

/**
 * \brief helper method to get data from a netxml-ups driver
 *
 * \param[in] port   - port (ip:port)
 * \param[out] out   - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata_netxml_ups(
        const std::string& port,
        map_string_t& out)
{
    map_string_t extra;
    extra["port"]=port;
    int loop=s_get_nut_dumpdata_loop();
    return nut_dumpdata("/lib/nut/netxml-ups",
            extra,
            loop,
            out);
}

/**
 * \brief helper method to get data from a dummy driver
 *
 * \param[in] device - dummy file device name (it is supposed to be in /etc/nut)
 * \param[out] out   - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata_dummy_ups(
        const std::string& device,
        map_string_t& out)
{
    map_string_t extra;
    extra["port"]=device;
    int loop=s_get_nut_dumpdata_loop();
    return nut_dumpdata("/lib/nut/dummy-ups",
            extra,
            loop,
            out);
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
nutdumpdata_test (bool verbose)
{
    printf (" * nutdumpdata ... \n");
    //drop and prepare a dummy dev file
    std::remove("/etc/nut/test.dev");
    std::ofstream testfile("/etc/nut/test.dev");
    if (testfile.is_open())
    {
      testfile << "key1: 1st\n";
      testfile << "key2: 2nd\n";
      testfile.close();
    }else{
        printf("WARNING : could not write to /etc/nut/test.dev \n");
        printf("WARNING : Try again with better priviledge (sudo make check) \n");
        printf (" * nutdumpdata: OK\n");
        return;
    }
    //set minimum loop
    set_nut_dumpdata_loop(1);
    map_string_t out;
    int rv=nut_dumpdata_dummy_ups("test.dev",out);
    if(rv!=0){
        printf("WARNING : can't find dummy-ups or --dump-data option is not available\n");
        printf("WARNING : check PATH and/or upgrade nut \n");
        printf (" * nutdumpdata: OK\n");
        return;
    }
    assert(out["key1"].compare("1st") == 0);
    assert(out["key2"].compare("2nd") == 0);

    //  @end
    printf (" * nutdumpdata: OK\n");
}
