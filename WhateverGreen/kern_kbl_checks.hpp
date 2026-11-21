#pragma once
#include <stdint.h>
#include <stddef.h>

namespace KBLFix {
constexpr uint32_t running=0xc0000000;
inline bool enabledArgument(bool present, uint32_t value) { return present && value==1; }
inline bool kernelPointer(uintptr_t p) { return p>=0xffff800000000000ULL && !(p&7); }
inline bool mappingFits(uintptr_t p,uint32_t n) {
    return kernelPointer(p) && n>=0x138130 && n<=0x1000000 && p<=UINTPTR_MAX-n;
}
inline bool wellStable(uint32_t p) {
    return p!=UINT32_MAX && (p&0x30000003)==0x30000003 &&
        ((p&running)==0 || (p&running)==running);
}
inline bool vco8100(uint32_t dpll) {
    if (dpll==UINT32_MAX) return false;
    const auto f=dpll&0x3f;
    return f==1 || f==3 || f==5 || f==7;
}
inline uint32_t decodeClock(uint32_t clock,uint32_t dpll) {
    if (clock==UINT32_MAX || !vco8100(dpll)) return 0;
    // Selector and decimal jointly identify the clock. Reserved/SSA fields do
    // not take part in the frequency comparison; reject the CDCLK override.
    if (clock&(1U<<19)) return 0;
    constexpr uint32_t khz[]={450000,540000,337500,675000};
    const auto f=khz[(clock>>26)&3];
    return (clock&0x7ff)==(f-1000+250)/500 ? f : 0;
}
inline uint32_t nativeTarget(bool flag540,bool dynamic,bool tcon) {
    return dynamic || tcon ? 0 : flag540 ? 540000 : 675000;
}
inline uint32_t fuseMaximum(uint32_t fuse) {
    if (fuse==UINT32_MAX) return 0;
    constexpr uint32_t maximum[]={675000,540000,450000,337500};
    return maximum[(fuse>>23)&3];
}
struct Engine {
    uint32_t clock,cached,power,pll,dbuf,dpll;
};
inline bool runningEngine(const Engine &s) {
    return wellStable(s.power) && s.pll!=UINT32_MAX && s.dbuf!=UINT32_MAX &&
        (s.pll&running)==running && (s.dbuf&running)==running &&
        decodeClock(s.clock,s.dpll)!=0 &&
        decodeClock(s.clock,s.dpll)==decodeClock(s.cached,s.dpll);
}
inline bool eligible(const Engine &s,uint32_t target,uint32_t fuse,uint32_t mailbox) {
    return (target==540000 || target==675000) && runningEngine(s) &&
        decodeClock(s.clock,s.dpll)<target && fuseMaximum(fuse)>=target &&
        mailbox!=UINT32_MAX && !(mailbox&0x80000000);
}
inline bool engineOff(uint32_t pll,uint32_t dbuf) {
    return pll!=UINT32_MAX && dbuf!=UINT32_MAX && !(pll&running) && !(dbuf&running);
}
inline bool restored(const Engine &s,uint32_t target) {
    return runningEngine(s) && decodeClock(s.clock,s.dpll)==target;
}
struct Outputs { uint32_t trans[4],ports[5],transport[5],planes[9],cursors[3]; };
inline bool noExternal(const Outputs &s) {
    for (unsigned i=0;i<3;++i) if (s.trans[i]==UINT32_MAX || (s.trans[i]&running)) return false;
    for (unsigned i=1;i<5;++i)
        if (s.ports[i]==UINT32_MAX || s.transport[i]==UINT32_MAX ||
            ((s.ports[i]|s.transport[i])&0x80000000)) return false;
    return true;
}
inline bool allStopped(const Outputs &s) {
    if (!noExternal(s) || s.trans[3]==UINT32_MAX || (s.trans[3]&running) ||
        s.ports[0]==UINT32_MAX || s.transport[0]==UINT32_MAX ||
        ((s.ports[0]|s.transport[0])&0x80000000)) return false;
    for (auto v:s.planes) if (v==UINT32_MAX || (v&0x80000000)) return false;
    for (auto v:s.cursors) if (v==UINT32_MAX || (v&0x3f)) return false;
    return true;
}
enum class Window:uint32_t { Open,Claimed,Closed };
// Pure transitions mirrored by CAS in the native wrapper; no elapsed-time retry.
inline Window nativeInit(Window s,bool first) { return first ? s : Window::Closed; }
inline Window modeDone(Window s,bool successfulRealMode) {
    return s==Window::Open && successfulRealMode ? Window::Closed : s;
}
inline bool equal(const uint8_t *a,const uint8_t *b,size_t n) {
    for(size_t i=0;i<n;++i) if(a[i]!=b[i]) return false;
    return true;
}
}
