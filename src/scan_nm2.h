#pragma once

#include <czmq.h>

/// Scan IP address using rest call
/// One device scan actor
void scan_nm2_actor(zsock_t* pipe, void* args);
