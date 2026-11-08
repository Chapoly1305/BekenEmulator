#include "matter_bridge.h"
#include "emulator.h"
#include "crypto_prims.h"
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

static const u32 CALLBACK=0x36a18, SEND=0xb37bc, RETURN_PC=0x4ef000;
static const u32 EVENT=0x4e0000, DATA=0x4e0100, STACK=0x4ff000;
MatterBridge::MatterBridge(BekenEmulator &emu,int port):e(emu),listener(-1),client(-1),active(false),ready(false),connected(false),pending_confirmations(0),started(0),wall_start(mono_time()) {
    if (port<1024 || port>65535) throw std::runtime_error("invalid Matter bridge port");
    if (hexstr(sha256(e.mem_.read_bytes(0x10000,1048372))) != "043e252596d5df47e0a4348b92cf1b6d3e5c01de088b54156ed33dc48a00feee")
        throw std::runtime_error("Matter SDK profile does not match application SHA256");
#ifndef _WIN32
    listener=socket(AF_INET,SOCK_STREAM,0);
    if(listener<0) throw std::runtime_error("Matter bridge socket failed");
    int one=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    sockaddr_in a;memset(&a,0,sizeof(a));a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons(port);
    if(bind(listener,(sockaddr*)&a,sizeof(a)) || listen(listener,1)) {close(listener);listener=-1;throw std::runtime_error("Matter bridge bind/listen failed");}
    fcntl(listener,F_SETFL,O_NONBLOCK);
#else
    throw std::runtime_error("Matter SDK bridge currently requires POSIX");
#endif
    e.trace_pc(SEND);e.trace_pc(RETURN_PC);
    out_write(strf("[MATTER_BRIDGE] SDK boundary, pinned 5118823e; listening 127.0.0.1:%d\n",port));out_flush();
}
MatterBridge::~MatterBridge(){
#ifndef _WIN32
 if(client>=0) close(client);
 if(listener>=0) close(listener);
#endif
}
void MatterBridge::fail(const std::string &s){out_write("[MATTER_BRIDGE] ERROR "+s+"\n");out_flush();e.stop();}
void MatterBridge::poll(){
#ifndef _WIN32
 if(client<0){client=accept(listener,0,0);if(client>=0){fcntl(client,F_SETFL,O_NONBLOCK);int one=1;setsockopt(client,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));out_write("[MATTER_BRIDGE] host attached\n");}}
 if(client<0)return;
 char buf[2048];ssize_t n=recv(client,buf,sizeof(buf),0);
 if(n>0)rx.append(buf,n);else if(n==0){close(client);client=-1;rx.clear();tx.clear();pending_confirmations=0;if(connected)queue.push_back(Event(2,Bytes()));connected=false;return;}
 else if(errno!=EAGAIN && errno!=EWOULDBLOCK){fail("socket receive failed");return;}
 while(rx.size()>=3){unsigned t=(u8)rx[0],len=(u8)rx[1]|((u8)rx[2]<<8);if(len>512){fail("frame too large");return;}if(rx.size()<len+3)return;
  if(t<1 || t>5 || (t!=3 && len!=0)){fail("unsupported host frame");return;}
  if(t==1) connected=true;
  if(t==2) connected=false;
  queue.push_back(Event(t,rx.substr(3,len)));rx.erase(0,3+len);
  if(queue.size()>64){fail("host queue overflow");return;}
 }
 if(!tx.empty()){n=send(client,tx.data(),tx.size(),MSG_NOSIGNAL);if(n>0){tx.erase(0,n);if(tx.empty()){while(pending_confirmations){queue.push_back(Event(6,Bytes()));--pending_confirmations;}}}else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)fail("socket send failed");}
#endif
}
void MatterBridge::begin(const Event &ev){
 e.cpu_.context_save(saved);active=true;started=e.state.insn_count;
 e.mem_.fill(EVENT,0,256);e.mem_.fill(DATA,0,512);
 unsigned event=0;u32 entry=CALLBACK;
 switch(ev.type){
 case 0:entry=0x230b4;break; // firmware's own matter_show command, for setup credentials
 case 1:event=6;break;       // peripheral connected; conn index 0
 case 2:event=7;e.mem_.phys_write(EVENT+1,1,0x13);break;
 case 3:event=1;e.mem_.phys_write(EVENT+4,2,2);e.mem_.write_bytes(DATA,ev.payload);e.mem_.phys_write(EVENT+12,2,ev.payload.size());break;
 case 4:case 5:event=1;e.mem_.phys_write(EVENT+4,2,5);e.mem_.phys_write(DATA,2,ev.type==4?2:0);e.mem_.phys_write(EVENT+12,2,2);break;
 case 7:entry=0x22e48;break; // application opens a basic commissioning window under the CHIP lock
 case 6:event=10;break;      // indication completion, generated after host send
 default:fail("invalid queued SDK event");return;
 }
 e.mem_.phys_write(EVENT+8,4,DATA);
 e.cpu_.reg_write(REG_SP,STACK);e.cpu_.reg_write(REG_LR,RETURN_PC|1);
 e.cpu_.reg_write(0,event);e.cpu_.reg_write(1,EVENT);e.cpu_.reg_write(2,0);e.cpu_.reg_write(3,0);
 e.cpu_.reg_write(REG_CPSR,(saved.cpsr & ~0x3fu)|MODE_SYS|PSR_T);
 e.cpu_.reg_write(REG_PC,entry);e.exc_epoch_++;
 out_write(strf("[MATTER_BRIDGE] SDK event %u (%u bytes) at %llu\n",event,(unsigned)ev.payload.size(),(unsigned long long)e.state.insn_count));out_flush();
}
void MatterBridge::tick(){
 double ahead=e.state.insn_count/5000000.0-(mono_time()-wall_start);
 if(ahead>0.002) sleep_ms((int)(ahead*1000));
 poll();
 if(active){if(e.state.insn_count-started>500000000)fail("SDK callback did not return");return;}
 if(e.state.insn_count<30000000)return;
 if(!ready){if(e.mem_.phys_read(0x3f476c,4)!=(CALLBACK|1))return;ready=true;queue.push_front(Event(7,Bytes()));queue.push_front(Event(0,Bytes()));out_write("[MATTER_BRIDGE] firmware callback registered\n");}
 u32 cpsr=e.cpu_.reg_read(REG_CPSR),sp=e.cpu_.reg_read(REG_SP);
 if(!queue.empty() && (cpsr & 0x1f)==MODE_SYS && !(cpsr&PSR_I) && e.state.idle_task_valid && sp>=e.state.idle_task_lo && sp<e.state.idle_task_hi){Event ev=queue.front();queue.pop_front();begin(ev);}
}
bool MatterBridge::hook(u32 pc){
 if(pc==RETURN_PC && active){
  // Callback may have been preempted; return only when its idle-task context resumes.
  for(int i=0;i<16;i++) e.cpu_.reg_write(i,saved.r[i]);
  e.cpu_.reg_write(REG_CPSR,saved.cpsr);
  active=false;e.exc_epoch_++;out_write("[MATTER_BRIDGE] SDK callback returned\n");out_flush();return true;
 }
 if(pc!=SEND || e.cpu_.reg_read(2)!=0 || e.cpu_.reg_read(3)!=4)return false;
 unsigned len=e.cpu_.reg_read(0);u32 p=e.cpu_.reg_read(1);
 if(len>512 || p<0x400000 || p+len>0x500000){fail("invalid indication buffer");return true;}
 Bytes payload=e.mem_.read_bytes(p,len);
 out_write(strf("[MATTER_BRIDGE] C2 %u bytes: %s\n",len,hexstr(payload).c_str()));out_flush();
 if(client<0){e.cpu_.reg_write(0,1);}else{tx+=Bytes(1,6)+p16le(len)+payload;e.cpu_.reg_write(0,0);++pending_confirmations;}
 u32 lr=e.cpu_.reg_read(REG_LR);e.cpu_.reg_write(REG_CPSR,(e.cpu_.reg_read(REG_CPSR)&~PSR_T)|((lr&1)?PSR_T:0));e.cpu_.reg_write(REG_PC,lr&~1u);
 return true;
}
