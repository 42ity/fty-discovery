/*  =========================================================================
    subprocess - C++ Wrapper around cxxtools::Fork

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
    subprocess - C++ Wrapper around cxxtools::Fork
@discuss
@end
*/

#include "fty_discovery_classes.h"

// forward declaration of helper functions
// TODO: move somewhere else

// small internal structure to be passed to callbacks
struct sbp_info_t {
    uint64_t timeout;
    uint64_t now;
    SubProcess *proc_p;
    std::stringstream &buff;
};

char * const * _mk_argv(const Argv& vec);
void _free_argv(char * const * argv);
std::size_t _argv_hash(Argv args);
static int s_output(SubProcess& p, std::string& o, std::string& e, uint64_t timeout, size_t timestep);
static int s_output2(SubProcess& p, std::string& o, uint64_t timeout, size_t timestep);


SubProcess::SubProcess(Argv cxx_argv, int flags) :
    _fork(false),
    _state(SubProcessState::NOT_STARTED),
    _cxx_argv(cxx_argv),
    _return_code(-1),
    _core_dumped(false)
{
    // made more verbose to increase readability of the code
    int stdin_flag = PIPE_DISABLED;
    int stdout_flag = PIPE_DISABLED;
    int stderr_flag = PIPE_DISABLED;

    if ((flags & SubProcess::STDIN_PIPE) != 0) {
        stdin_flag = PIPE_DEFAULT;
    }
    if ((flags & SubProcess::STDOUT_PIPE) != 0) {
        stdout_flag = PIPE_DEFAULT;
    }
    if ((flags & SubProcess::STDERR_PIPE) != 0) {
        stderr_flag = PIPE_DEFAULT;
    }

    _inpair[0]  = stdin_flag;  _inpair[1]  = stdin_flag;
    _outpair[0] = stdout_flag; _outpair[1] = stdout_flag;
    _errpair[0] = stderr_flag; _errpair[1] = stderr_flag;
}

SubProcess::~SubProcess() {
    int _saved_errno = errno;

    // update a state
    poll();
    // Graceful shutdown
    if (isRunning())
        kill(SIGTERM);
    for (int i = 0; i<20 && isRunning(); i++) {
        usleep(100);
        poll(); // update a state after awhile
    }
    if (isRunning()) {
        // wait is already inside terminate
        terminate();
    }

    // close pipes
    ::close(_inpair[0]);
    ::close(_outpair[0]);
    ::close(_errpair[0]);
    ::close(_inpair[1]);
    ::close(_outpair[1]);
    ::close(_errpair[1]);

    errno = _saved_errno;
}

//note: the extra space at the end of the string doesn't really matter
std::string SubProcess::argvString() const
{
    std::string ret;
    for (std::size_t i = 0, l = _cxx_argv.size();
         i < l;
         ++i) {
        ret.append (_cxx_argv.at(i));
        ret.append (" ");
    }
    return ret;
}

bool SubProcess::run() {

    int status;
    // do nothing if some process has been already started
    if (_state != SubProcessState::NOT_STARTED) {
        return true;
    }

    // create pipes
    if (_inpair[0] != PIPE_DISABLED && ::pipe(_inpair) == -1) {
        return false;
    }
    if (_outpair[0] != PIPE_DISABLED && ::pipe(_outpair) == -1) {
        return false;
    }
    if (_errpair[0] != PIPE_DISABLED && ::pipe(_errpair) == -1) {
        return false;
    }

    _fork.fork();
    if (_fork.child()) {

        if (_inpair[0] != PIPE_DISABLED) {
            int o_flags = fcntl(_inpair[0], F_GETFL);
            int n_flags = o_flags & (~O_NONBLOCK);
            fcntl(_inpair[0], F_SETFL, n_flags);
            ::dup2(_inpair[0], STDIN_FILENO);
            ::close(_inpair[1]);
        }
        if (_outpair[0] != PIPE_DISABLED) {
            ::close(_outpair[0]);
            ::dup2(_outpair[1], STDOUT_FILENO);
        }
        if (_errpair[0] != PIPE_DISABLED) {
            ::close(_errpair[0]);
            ::dup2(_errpair[1], STDERR_FILENO);
        }

        // enter in stopped state to warn parent
        ::kill(getpid(), SIGSTOP);
        auto argv = _mk_argv(_cxx_argv);
        if (!argv) {
            // need to exit from the child gracefully
            exit(ENOMEM);
        }

        ::execvp(argv[0], argv);
        // We can get here only if execvp failed
        exit(errno);

    }
    // we are in parent
    _state = SubProcessState::RUNNING;
    //make sure child make fd operations before continue.
    waitpid(_fork.getPid(), &status, WUNTRACED);
    //wake up child
    ::kill(_fork.getPid(), SIGCONT);
    ::close(_inpair[0]);
    ::close(_outpair[1]);
    ::close(_errpair[1]);
    // update a state
    poll();
    return true;
}

int SubProcess::wait(bool no_hangup)
{
    //thanks tomas for the fix!
    int status = -1;

    int options = no_hangup ? WNOHANG : 0;

    if (_state != SubProcessState::RUNNING) {
        return _return_code;
    }

    int ret = ::waitpid(getPid(), &status, options);
    if (no_hangup && ret == 0) {
        // state did not change here
        return _return_code;
    }

    if (WIFEXITED(status)) {
        _state = SubProcessState::FINISHED;
        _return_code = WEXITSTATUS(status);
    }
    else if (WIFSIGNALED(status)) {
        _state = SubProcessState::FINISHED;
        _return_code = - WTERMSIG(status);

        if (WCOREDUMP(status)) {
            _core_dumped = true;
        }
    }
    // we don't allow wait on SIGSTOP/SIGCONT, so WIFSTOPPED/WIFCONTINUED
    // were omited here

    return _return_code;
}

int SubProcess::wait(unsigned int timeout)
{
    while( true ) {
        poll();
        if (_state != SubProcessState::RUNNING) {
            return _return_code;
        }
        if( ! timeout ) {
            return _return_code;
        }
        sleep(1);
        --timeout;
    }
}

int SubProcess::kill(int signal) {
    auto ret = ::kill(getPid(), signal);
    poll();
    return ret;
}

int SubProcess::terminate() {
    auto ret = kill(SIGKILL);
    wait();
    return ret;
}

const char* SubProcess::state() const {
    if (_state == SubProcess::SubProcessState::NOT_STARTED) {
        return "not-started";
    }
    else if (_state == SubProcess::SubProcessState::RUNNING) {
        return "running";
    }
    else if (_state == SubProcess::SubProcessState::FINISHED) {
        return "finished";
    }

    return "unimplemented state";
}

std::string read_all(int fd) {
    static size_t BUF_SIZE = 4096;
    char buf[4096+1];
    ssize_t r;

    std::stringbuf sbuf;

    while (true) {
        memset(buf, '\0', BUF_SIZE+1);
        r = ::read(fd, buf, BUF_SIZE);

        //TODO what to do if errno != EAGAIN | EWOULDBLOCK
        if (r <= 0) {
            break;
        }
        sbuf.sputn(buf, strlen(buf));
    }
    return sbuf.str();
}

int call(const Argv& args) {
    SubProcess p(args);
    p.run();
    return p.wait();
}

int output(const Argv& args, std::string& o, std::string& e, uint64_t timeout, size_t timestep) {
    SubProcess p(args, SubProcess::STDOUT_PIPE | SubProcess::STDERR_PIPE);
    return s_output (p, o, e, timeout, timestep);
}

int output2(const Argv& args, std::string& o, uint64_t timeout, size_t timestep) {
    SubProcess p(args, SubProcess::STDOUT_PIPE);
    return s_output2 (p, o, timeout, timestep);
}

int output(const Argv& args, std::string& o, std::string& e, const std::string& i, uint64_t timeout, size_t timestep) {
    SubProcess p(args, SubProcess::STDOUT_PIPE | SubProcess::STDERR_PIPE| SubProcess::STDIN_PIPE);
    p.run();
    int r = ::write(p.getStdin(), i.c_str(), i.size());
    ::fsync(p.getStdin());
    ::close(p.getStdin());
    if (r == -1)
        return r;
    return s_output (p, o, e, timeout, timestep);
}

std::string wait_read_all(int fd) {
    static size_t BUF_SIZE = 4096;
    char buf[4096+1];
    ssize_t r;
    int exit = 0;

    int o_flags = fcntl(fd, F_GETFL);
    int n_flags = o_flags | O_NONBLOCK;
    fcntl(fd, F_SETFL, n_flags);

    std::stringbuf sbuf;
    memset(buf, '\0', BUF_SIZE+1);
    errno = 0;
    while (::read(fd, buf, BUF_SIZE) <= 0 &&
           (errno == EAGAIN || errno == EWOULDBLOCK) && exit < 5000) {
        usleep(1000);
        errno = 0;
        exit++;
    }

    sbuf.sputn(buf, strlen(buf));

    exit = 0;
    while (true) {
        memset(buf, '\0', BUF_SIZE+1);
        errno = 0;
        r = ::read(fd, buf, BUF_SIZE);
        if (r <= 0) {
            if(exit > 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
                break;
            usleep(1000);
            exit = 1;
        } else {
            exit = 0;
        }
        sbuf.sputn(buf, strlen(buf));
    }
    fcntl(fd, F_SETFL, o_flags);
    return sbuf.str();
}

// ### helper functions ###
char * const * _mk_argv(const Argv& vec) {

    char ** argv = (char **) malloc(sizeof(char*) * (vec.size()+1));
    assert(argv);

    for (auto i=0u; i != vec.size(); i++) {

        auto str = vec[i];
        char* dest = (char*) malloc(sizeof(char) * (str.size() + 1));
        memcpy(dest, str.c_str(), str.size());
        dest[str.size()] = '\0';

        argv[i] = dest;
    }
    argv[vec.size()] = NULL;
    return (char * const*)argv;
}

void _free_argv(char * const * argv) {
    char *foo;
    std::size_t n;

    n = 0;
    while((foo = argv[n]) != NULL) {
        free(foo);
        n++;
    }
    free((void*)argv);
}

std::size_t _argv_hash(Argv args) {


    std::hash<std::string> hash;
    size_t ret = hash("");

    for (auto str : args) {
        size_t foo = hash(str);
        ret = ret ^ (foo << 1);
    }

    return ret;
}

/*  ZLOOP AND PROPER TIMEOUT SUPPORT */

// add file descriptor to zloop
static int
xzloop_add_fd (zloop_t *self, int fd, zloop_fn handler, void *arg)
{
    assert (self);
    zmq_pollitem_t *fditem = (zmq_pollitem_t*) zmalloc (sizeof (zmq_pollitem_t));
    assert (fditem);
    fditem->fd = fd;
    fditem->events = ZMQ_POLLIN;

    int r = zloop_poller (self, fditem, handler, arg);
    free (fditem);
    return r;
}

// handle incoming data on fd
static int
s_handler (zloop_t *loop, zmq_pollitem_t *item, void *arg)
{
    assert (loop); //remove compiler warning
    struct sbp_info_t *i = (struct sbp_info_t*) arg;

    //XXX: read_all is not a good idea for write intensive processes (like ping)
    //     because s_handler won't return - so lets read only PIPE_BUF and exit
    char buf[PIPE_BUF+1];
    memset(buf, '\0', PIPE_BUF+1);
    int r = ::read(item->fd, buf, PIPE_BUF);
    i->buff << buf;

    return r;
}

// ping the process
static int
s_ping_process (zloop_t *loop, int timer_id, void *args)
{
    assert (loop); //remove compiler warning
    struct sbp_info_t *i = (struct sbp_info_t*) args;

    if (zsys_interrupted)   // end the loop when signal is delivered
        return -1;

    i->proc_p->poll ();
    if (!i->proc_p->isRunning ())
        return -1;
    return 0;
}

// stop the loop
static int
s_end_loop (zloop_t *loop, int timer_id, void *args)
{
    return -1;
}

static int s_output(SubProcess& p, std::string& o, std::string& e, uint64_t timeout, size_t timestep)
{
    std::stringstream out;
    std::stringstream err;

    sbp_info_t out_info {timeout * 1000, (uint64_t) zclock_mono (), &p, out};
    sbp_info_t err_info {timeout * 1000, (uint64_t) zclock_mono (), &p, err};

    p.run();

    zloop_t *loop = zloop_new ();
    assert (loop);

    if (timeout != 0)
        zloop_timer (loop, timeout * 1000, 1, s_end_loop, NULL);
    zloop_timer (loop, timestep, 0, s_ping_process, &out_info);
    xzloop_add_fd (loop, p.getStdout (), s_handler, &out_info);
    xzloop_add_fd (loop, p.getStderr (), s_handler, &err_info);
    zloop_start (loop);

    zloop_destroy (&loop);

    int r = p.poll ();
    if (p.isRunning ()) {
        p.kill ();
        r = p.poll ();
        if (p.isRunning ()) {
            zclock_sleep (2000);
            p.terminate ();
            r = p.poll ();
        }
    }

    out << read_all (p.getStdin ());
    err << read_all (p.getStderr ());

    o.assign(out.str ());
    e.assign(err.str ());
    return r;
}

static int s_output2(SubProcess& p, std::string& o, uint64_t timeout, size_t timestep)
{
    std::stringstream out;

    sbp_info_t out_info {timeout * 1000, (uint64_t) zclock_mono (), &p, out};

    p.run();

    zloop_t *loop = zloop_new ();
    assert (loop);

    if (timeout != 0)
        zloop_timer (loop, timeout * 1000, 1, s_end_loop, NULL);
    zloop_timer (loop, timestep, 0, s_ping_process, &out_info);
    xzloop_add_fd (loop, p.getStdout (), s_handler, &out_info);
    zloop_start (loop);

    zloop_destroy (&loop);

    int r = p.poll ();
    if (p.isRunning ()) {
        p.kill ();
        r = p.poll ();
        if (p.isRunning ()) {
            zclock_sleep (2000);
            p.terminate ();
            r = p.poll ();
        }
    }

    out << read_all (p.getStdin ());

    o.assign(out.str ());
    return r;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
subprocess_test (bool verbose)
{
    printf (" * subprocess: ");

    //  @selftest
    //  @end
    printf ("Empty test - OK\n");
}
