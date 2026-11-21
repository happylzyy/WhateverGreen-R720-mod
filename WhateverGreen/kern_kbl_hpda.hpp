#pragma once
#include "kern_kbl_checks.hpp"
namespace KBLFix {
constexpr uint8_t hpdOriginal[]={
    0x31,0xc0,0x48,0x85,0xf6,0x0f,0x95,0xc0,0x48,0x8b,0x8b,0x08,0x1a,0x00,0x00,
    0xc1,0xe0,0x1c,0x0b,0x81,0x30,0x40,0x0c,0x00,0x0d,0x10,0x10,0x10,0x00,
    0x89,0x81,0x30,0x40,0x0c,0x00};
constexpr uint8_t hpdPatched[]={
    0x31,0xc0,0x48,0x85,0xf6,0x0f,0x95,0xc0,0x48,0x8b,0x8b,0x08,0x1a,0x00,0x00,
    0xc1,0xe0,0x1c,0x0b,0x81,0x30,0x40,0x0c,0x00,0x0d,0x10,0x10,0x10,0x10,
    0x89,0x81,0x30,0x40,0x0c,0x00};
enum class Flow { Next,Call,Conditional,Jump,Return,Reject };
struct Instruction { unsigned length; Flow flow; int32_t displacement; };
enum class HPDState { Mismatch,Original,AlreadyPatched };
struct HPDMatch { HPDState state; size_t offset; };
// Follow only instructions reachable from entry, never calls into another
// function. `bound` is a symbol-derived upper bound, not a hardcoded length.
// Caller supplies zeroed marks[bound] and a 1024-entry worklist.
template<class Decode> HPDMatch inspectHPD(const uint8_t *p,size_t bound,
                                         uint8_t *marks,uint32_t *work,Decode decode) {
    const HPDMatch bad {HPDState::Mismatch,0};
    if(!p || !marks || !work || !bound || bound>65536) return bad;
    size_t top=1,original=0,patched=0,found=0; work[0]=0;
    while(top) {
        size_t pos=work[--top];
        for(;;) {
            if(pos>=bound || marks[pos]==2) return {HPDState::Mismatch,pos};
            if(marks[pos]==1) break;
            auto insn=decode(p+pos,bound-pos);
            if(!insn.length || insn.length>15 || insn.length>bound-pos || insn.flow==Flow::Reject) return {HPDState::Mismatch,pos};
            for(size_t i=0;i<insn.length;++i) if(marks[pos+i]) return {HPDState::Mismatch,pos};
            marks[pos]=1;
            for(size_t i=1;i<insn.length;++i) marks[pos+i]=2;
            if(bound-pos>=sizeof(hpdOriginal)) {
                if(equal(p+pos,hpdOriginal,sizeof(hpdOriginal))) { ++original;found=pos; }
                if(equal(p+pos,hpdPatched,sizeof(hpdPatched))) { ++patched;found=pos; }
            }
            if(insn.flow==Flow::Return) break;
            // A compiler may end the symbol with a call to a non-returning
            // helper (the audited function ends in panic). Never cross the
            // symbol bound to infer what that helper does.
            if(insn.flow==Flow::Call && pos+insn.length==bound) break;
            if(insn.flow==Flow::Conditional || insn.flow==Flow::Jump) {
                const int64_t target=int64_t(pos)+insn.length+insn.displacement;
                if(target<0 || uint64_t(target)>=bound) return {HPDState::Mismatch,pos};
                if(insn.flow==Flow::Jump) { pos=size_t(target);continue; }
                if(top==1024) return bad;
                work[top++]=uint32_t(target);
            }
            pos+=insn.length;
        }
    }
    if(original==1 && patched==0) return {HPDState::Original,found};
    if(original==0 && patched==1) return {HPDState::AlreadyPatched,found};
    return bad;
}
}
