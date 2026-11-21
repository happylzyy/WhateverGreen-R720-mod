// Opt-in SKL/KBL display fixes. All clock writes use reviewed Apple methods.
#include "kern_kbl_display.hpp"
#include "kern_kbl_checks.hpp"
#include "kern_kbl_decoder.hpp"
#include "kern_kbl_sha256.hpp"
#include "kern_kbl_abi.hpp"
#include <Headers/kern_cpu.hpp>
#include <Headers/kern_disasm.hpp>
#include <Headers/kern_util.hpp>
#include <IOKit/IOLocks.h>
#include <kern/thread.h>

namespace KBLDisplay {
using namespace KBLFix;
static bool hpdEnabled=false,clockEnabled=false,prepared=false,fullModesetReady=false;
static uint32_t armed=0,window=uint32_t(Window::Open),nativeInitSeen=0;
static uintptr_t startupController=0,ownerThread=0;
static void *ownerController=nullptr,*ownerFramebuffer=nullptr;
using SetMode=int32_t (*)(void *,void *,void *,const void *);
using Disable=int32_t (*)(void *,void *,void *,bool,uint8_t);
using EngineFn=void (*)(void *);
static SetMode originalSetMode=nullptr;
static Disable disableDisplay=nullptr;
static EngineFn originalUninit=nullptr,originalInit=nullptr;
static mach_vm_address_t nativeFunctions[7] {};

#ifdef DEBUG
static IORegistryEntry *gpu=nullptr;
static void diag(const char *property,const char *state) {
    DBGLOG("igfx","KBL display %s: %s",property,state);
    if(gpu) gpu->setProperty(property,state);
}
#define CLOCK_DIAG(s) diag("KBLCDCLKStatus",s)
#define HPD_DIAG(s) diag("KBLHPDAStatus",s)
#else
#define CLOCK_DIAG(s) do {} while(0)
#define HPD_DIAG(s) do {} while(0)
#endif

void select(DeviceInfo *info) {
    uint32_t hpd=0,clock=0;
    const bool hpdPresent=PE_parse_boot_argn("igfxhpdafix",&hpd,sizeof(hpd));
    const bool clockPresent=PE_parse_boot_argn("igfxcdclkfix",&clock,sizeof(clock));
    hpdEnabled=enabledArgument(hpdPresent,hpd);
    clockEnabled=enabledArgument(clockPresent,clock);
    if(!hpdEnabled && !clockEnabled) return;
    const auto gen=BaseDeviceInfo::get().cpuGeneration;
    if(!info->videoBuiltin || (gen!=CPUInfo::CpuGeneration::Skylake && gen!=CPUInfo::CpuGeneration::KabyLake)) {
        hpdEnabled=clockEnabled=false;
        SYSLOG("igfx","KBL display fixes require SKL/KBL display hardware");
        return;
    }
#ifdef DEBUG
    gpu=info->videoBuiltin;gpu->retain();
    gpu->setProperty("KBLDisplayFixBuild","v1-debug");
    if(hpdEnabled) HPD_DIAG("waiting-for-kbl-framebuffer");
    if(clockEnabled) CLOCK_DIAG("waiting-for-kbl-framebuffer");
#endif
}
bool hpdRequested() { return hpdEnabled; }
bool cdclkRequested() { return clockEnabled; }
void deinit() {
    __atomic_store_n(&armed,0U,__ATOMIC_RELEASE);
    hpdEnabled=clockEnabled=false;
#ifdef DEBUG
    if(gpu) { gpu->release();gpu=nullptr; }
#endif
}

void applyHPD(KernelPatcher &patcher,size_t index,mach_vm_address_t address,size_t size,KernelPatcher::KextInfo *kext) {
    if(!hpdEnabled || !address || size>UINT64_MAX-address) return;
    patcher.clearError();
    const auto start=patcher.solveSymbol(index,"__ZN31AppleIntelFramebufferController18hwEnableInterruptsEv",address,size);
    const auto end=patcher.solveSymbol(index,"__ZN31AppleIntelFramebufferController24createMEClientControllerEv",address,size);
    const bool range=patcher.getError()==KernelPatcher::Error::NoError && start>=address && end>start &&
        end-address<size && end-start<=65536;
    patcher.clearError();
    if(!range) { HPD_DIAG("skipped-symbol-bound");return; }
    const size_t bound=end-start,allocation=bound+1024*sizeof(uint32_t)+4;
    auto memory=Buffer::create<uint8_t>(allocation);
    if(!memory) { SYSLOG("igfx","HPD-A allocation failed");return; }
    bzero(memory,allocation);
    auto work=reinterpret_cast<uint32_t *>(memory+((bound+3)&~size_t(3)));
    auto bytes=reinterpret_cast<uint8_t *>(start);
    const auto match=inspectHPD(bytes,bound,memory,work,[](const uint8_t *p,size_t n) {
        return decodeHPD(p,n,[](const uint8_t *b,hde64s *h) { Disassembler::hdeDisasm(reinterpret_cast<mach_vm_address_t>(b),h); });
    });
    Buffer::deleter(memory);
    if(match.state==HPDState::AlreadyPatched) { HPD_DIAG("already-present");return; }
    if(match.state!=HPDState::Original) { HPD_DIAG("skipped-instruction-graph");return; }
    KernelPatcher::LookupPatch patch {};
    patch.kext=kext;patch.find=hpdOriginal;patch.replace=hpdPatched;
    patch.size=sizeof(hpdOriginal);patch.count=1;
    // Lilu's end is exclusive: one extra mapped byte admits this candidate.
    patcher.applyLookupPatch(&patch,bytes+match.offset,sizeof(hpdOriginal)+1);
    const auto error=patcher.getError();patcher.clearError();
    if(error!=KernelPatcher::Error::NoError) { SYSLOG("igfx","HPD-A patch failed");return; }
#ifdef DEBUG
    HPD_DIAG(equal(bytes+match.offset,hpdPatched,sizeof(hpdPatched)) ? "applied-verified" : "failed-debug-byte-verification");
#endif
}

template<class T> static T field(const void *object,size_t offset) {
    T value;__builtin_memcpy(&value,static_cast<const uint8_t *>(object)+offset,sizeof(value));return value;
}
static uint32_t read(uintptr_t base,uint32_t reg) { return *reinterpret_cast<volatile const uint32_t *>(base+reg); }
static Engine readEngine(void *c,uintptr_t base) {
    return {read(base,0x46000),field<uint32_t>(c,0x2ea0),read(base,0x45404),
            read(base,0x46010),read(base,0x45008),read(base,0x6c058)};
}
static Outputs readOutputs(uintptr_t base,bool stopping) {
    Outputs s {};
    for(unsigned i=0;i<3;++i) s.trans[i]=read(base,0x70008+0x1000*i);
    for(unsigned i=stopping?0:1;i<5;++i) {
        s.ports[i]=read(base,0x64000+0x100*i);s.transport[i]=read(base,0x64040+0x100*i);
    }
    if(stopping) {
        s.trans[3]=read(base,0x7f008);
        for(unsigned p=0;p<3;++p) {
            s.cursors[p]=read(base,0x70080+0x1000*p);
            for(unsigned i=0;i<3;++i) s.planes[p*3+i]=read(base,0x70180+0x1000*p+0x100*i);
        }
    }
    return s;
}
#ifdef DEBUG
static void snapshot(const char *name,void *c,uintptr_t base,uint32_t target) {
    auto s=readEngine(c,base);auto o=readOutputs(base,true);char text[512];
    snprintf(text,sizeof(text),
        "clock=%08x cache=%08x khz=%u target=%u pw=%08x pll=%08x dbuf=%08x dpll=%08x fuse=%08x mailbox=%08x trans=%08x,%08x,%08x,%08x ports=%08x,%08x,%08x,%08x,%08x stopped=%u",
        s.clock,s.cached,decodeClock(s.clock,s.dpll),target,s.power,s.pll,s.dbuf,s.dpll,read(base,0x51000),read(base,0x138124),
        o.trans[0],o.trans[1],o.trans[2],o.trans[3],o.ports[0],o.ports[1],o.ports[2],o.ports[3],o.ports[4],unsigned(allStopped(o)));
    diag(name,text);
}
#define SNAP(name,c,b,t) snapshot(name,c,b,t)
#else
#define SNAP(name,c,b,t) do {} while(0)
#endif

static Window currentWindow() { return Window(__atomic_load_n(&window,__ATOMIC_ACQUIRE)); }
static bool transition(Window from,Window to) {
    uint32_t expected=uint32_t(from);
    return __atomic_compare_exchange_n(&window,&expected,uint32_t(to),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
static void closeWindow() { __atomic_store_n(&window,uint32_t(Window::Closed),__ATOMIC_RELEASE); }
static void wrappedInit(void *c) {
    const bool active=__atomic_load_n(&armed,__ATOMIC_ACQUIRE);
    // Firmware-initialized boots can make zero initDisplayEngine calls before
    // hwSetMode. Do not require an init callback to open the startup window.
    if(active) {
        const bool first=__atomic_exchange_n(&nativeInitSeen,1U,__ATOMIC_ACQ_REL)==0;
        if(nativeInit(currentWindow(),first)==Window::Closed) closeWindow();
    }
    originalInit(c);
}
static void wrappedUninit(void *c) {
    if(__atomic_load_n(&armed,__ATOMIC_ACQUIRE)) closeWindow();
    originalUninit(c);
}
bool forceModeUpdate(void *c,void *fb) {
    return __atomic_load_n(&ownerThread,__ATOMIC_ACQUIRE)==reinterpret_cast<uintptr_t>(current_thread()) &&
        ownerController==c && ownerFramebuffer==fb;
}
static int32_t forwardMode(void *c,void *fb,void *path,const void *timing,bool real) {
    auto result=originalSetMode(c,fb,path,timing);
    if(real && result==0) transition(Window::Open,modeDone(Window::Open,true));
    return result;
}
static int32_t wrappedSetMode(void *c,void *fb,void *path,const void *timing) {
    if(!__atomic_load_n(&armed,__ATOMIC_ACQUIRE) || currentWindow()!=Window::Open)
        return originalSetMode(c,fb,path,timing);
    if(!kernelPointer(reinterpret_cast<uintptr_t>(c)) || !kernelPointer(reinterpret_cast<uintptr_t>(fb)) ||
       !kernelPointer(reinterpret_cast<uintptr_t>(path)) || !timing) return forwardMode(c,fb,path,timing,false);
    uintptr_t expectedController=0;
    __atomic_compare_exchange_n(&startupController,&expectedController,reinterpret_cast<uintptr_t>(c),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    if(reinterpret_cast<uintptr_t>(c)!=__atomic_load_n(&startupController,__ATOMIC_ACQUIRE))
        return originalSetMode(c,fb,path,timing);
    if(field<uint32_t>(path,0x28)!=3) {
        closeWindow();CLOCK_DIAG("skipped-external-startup-modeset");return originalSetMode(c,fb,path,timing);
    }
    const auto base=field<uintptr_t>(c,0x1a08),lockAddress=field<uintptr_t>(c,0x1a10);
    if(!mappingFits(base,field<uint32_t>(c,0x1d30)) || !kernelPointer(lockAddress)) {
        CLOCK_DIAG("deferred-unready-mapping-or-lock");return forwardMode(c,fb,path,timing,true);
    }
    auto lock=reinterpret_cast<IORecursiveLock *>(lockAddress);
    IORecursiveLockLock(lock);
    // Re-check after acquiring the same lock the native methods use.
    if(currentWindow()!=Window::Open) { IORecursiveLockUnlock(lock);return originalSetMode(c,fb,path,timing); }
    const auto platform=field<uintptr_t>(c,0x1de8);
    const bool single=field<uint32_t>(fb,0xb930)==1 &&
        field<uintptr_t>(fb,0xb938)==reinterpret_cast<uintptr_t>(path) &&
        field<uint8_t>(path,0x450)==0 && field<uint32_t>(path,0x458)<3 &&
        field<uint32_t>(path,0x490)!=0 && kernelPointer(field<uintptr_t>(path,0x20)) &&
        kernelPointer(field<uintptr_t>(path,0x4a0));
    const uint32_t target=kernelPointer(platform) ? nativeTarget(
        field<uint8_t>(reinterpret_cast<void *>(platform),0x61)&4,
        field<uint8_t>(c,0x3a8c)&1,field<uintptr_t>(c,0x2e50)!=0) : 0;
    if(!single || !target) {
        CLOCK_DIAG("skipped-object-or-native-policy");
        IORecursiveLockUnlock(lock);return forwardMode(c,fb,path,timing,true);
    }
    const auto before=readEngine(c,base);
    const auto fuse=read(base,0x51000),mailbox=read(base,0x138124);
    const auto external=readOutputs(base,false);
    SNAP("KBLCDCLKBefore",c,base,target);
    if(!eligible(before,target,fuse,mailbox) || !noExternal(external)) {
        CLOCK_DIAG("skipped-clock-power-or-active-external");
        IORecursiveLockUnlock(lock);return forwardMode(c,fb,path,timing,true);
    }
    if(!transition(Window::Open,Window::Claimed)) { IORecursiveLockUnlock(lock);return originalSetMode(c,fb,path,timing); }
    ownerController=c;ownerFramebuffer=fb;
    __atomic_store_n(&ownerThread,reinterpret_cast<uintptr_t>(current_thread()),__ATOMIC_RELEASE);
    const int32_t stopped=disableDisplay(c,fb,path,false,0);
    const auto stoppedEngine=readEngine(c,base);
    const auto stoppedOutputs=readOutputs(base,true);
    const auto stoppedFuse=read(base,0x51000),stoppedMailbox=read(base,0x138124);
    SNAP("KBLCDCLKStopped",c,base,target);
    bool allowModeset=false,resetOK=false;
    unsigned failure=0;
    if(stopped!=0 || !allStopped(stoppedOutputs) || !eligible(stoppedEngine,target,stoppedFuse,stoppedMailbox)) {
        failure=1;allowModeset=runningEngine(stoppedEngine);
    } else {
        // Call original trampolines: this transaction does not reopen lifecycle.
        originalUninit(c);
        const auto pll=read(base,0x46010),dbuf=read(base,0x45008);
        SNAP("KBLCDCLKEngineOff",c,base,target);
        if(!engineOff(pll,dbuf)) failure=2;
        else {
            originalInit(c);
            const auto initialized=readEngine(c,base);
            SNAP("KBLCDCLKInitialized",c,base,target);
            resetOK=allowModeset=restored(initialized,target);
            if(!resetOK) failure=3;
        }
    }
    // Do not re-enter modeset on an engine whose stop/init failed. No retry.
    const int32_t result=allowModeset ? originalSetMode(c,fb,path,timing) : int32_t(kIOReturnError);
    if(failure || result!=0) SYSLOG("igfx","CDCLK native sequence failed: stage=%u modeset=%08x",failure,unsigned(result));
    SNAP("KBLCDCLKAfter",c,base,target);
    if(resetOK && result==0) CLOCK_DIAG("applied-native-target");
    else CLOCK_DIAG("failed-or-aborted-native-sequence");
    __atomic_store_n(&ownerThread,uintptr_t(0),__ATOMIC_RELEASE);
    ownerController=nullptr;ownerFramebuffer=nullptr;
    closeWindow();IORecursiveLockUnlock(lock);
    return result;
}

static bool verifyABI(KernelPatcher &patcher,size_t index,mach_vm_address_t address,size_t size,unsigned i) {
    patcher.clearError();
    const auto f=patcher.solveSymbol(index,abi[i].symbol,address,size);
    const auto end=patcher.solveSymbol(index,abi[i].end,address,size);
    const bool range=patcher.getError()==KernelPatcher::Error::NoError && f>=address && end>f &&
        end-address<size && end-f==abi[i].size;
    patcher.clearError();if(!range) return false;
    uint8_t digest[32];sha256(reinterpret_cast<const uint8_t *>(f),abi[i].size,digest);
    if(!equal(digest,abi[i].digest,sizeof(digest))) return false;
    nativeFunctions[i]=f;return true;
}
bool prepare(KernelPatcher &patcher,size_t index,mach_vm_address_t address,size_t size) {
    if(!clockEnabled || !address || size>UINT64_MAX-address) return false;
    for(unsigned i=0;i<sizeof(abi)/sizeof(abi[0]);++i)
        if(!verifyABI(patcher,index,address,size,i)) {
            CLOCK_DIAG("skipped-unknown-native-abi");return false;
        }
    disableDisplay=reinterpret_cast<Disable>(nativeFunctions[2]);
    prepared=true;return true;
}
void modesetRouteReady(bool ready) { if(prepared) fullModesetReady=ready; }
void install(KernelPatcher &patcher,size_t index,mach_vm_address_t address,size_t size) {
    // Keep prepare's ABI failure reason instead of overwriting it with a later
    // missing-route status. In Release neither diagnostic path is compiled.
    if(!prepared) return;
    if(!fullModesetReady) { CLOCK_DIAG("skipped-modeset-route");return; }
    // Other WEG submodules ran after prepare. Reject unexpected modifications;
    // hwRegsNeedUpdate is intentionally already routed by WEG's FCM module.
    for(unsigned i=0;i<sizeof(abi)/sizeof(abi[0]);++i)
        if(i!=1 && !verifyABI(patcher,index,address,size,i)) { CLOCK_DIAG("skipped-route-conflict");return; }
    KernelPatcher::RouteRequest routes[]={
        {abi[0].symbol,wrappedSetMode,originalSetMode},
        {abi[3].symbol,wrappedUninit,originalUninit},
        {abi[4].symbol,wrappedInit,originalInit}};
    if(!patcher.routeMultiple(index,routes,3,address,size) || !originalSetMode || !originalUninit || !originalInit) {
        patcher.clearError();SYSLOG("igfx","CDCLK native routes failed; feature not armed");return;
    }
    __atomic_store_n(&armed,1U,__ATOMIC_RELEASE);
    CLOCK_DIAG("armed-initial-modeset-window");
}
}
