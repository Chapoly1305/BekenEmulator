#ifndef BK_MATTER_BRIDGE_H
#define BK_MATTER_BRIDGE_H
#include "arm_cpu.h"
#include <deque>
class BekenEmulator;
// Explicit, hash-pinned SDK boundary; does not model the BLE radio.
class MatterBridge {
public:
    MatterBridge(BekenEmulator &emu, int port);
    ~MatterBridge();
    void tick();
    bool hook(u32 pc);
private:
    struct Event { unsigned type; Bytes payload; Event(unsigned t, const Bytes &p):type(t),payload(p){} };
    BekenEmulator &e;
    int listener,client;
    Bytes rx,tx;
    std::deque<Event> queue;
    bool active,ready,connected;
    unsigned pending_confirmations;
    CpuContext saved;
    u64 started;
    double wall_start;
    void poll();
    void begin(const Event &event);
    void fail(const std::string &reason);
};
#endif
