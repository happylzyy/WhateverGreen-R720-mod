#pragma once
#include "kern_kbl_hpda.hpp"
#include <Headers/hde64.h>
namespace KBLFix {
template<class NativeDecode> inline Instruction decodeHPD(const uint8_t *p,size_t n,NativeDecode native) {
    uint8_t local[32] {}; const auto count=n<sizeof(local)?n:sizeof(local);
    __builtin_memcpy(local,p,count);
    hde64s h {};
    native(local,&h);
    if(!h.len || h.len>n || (h.flags&F_ERROR)) return {0,Flow::Reject,0};
    if(h.opcode==0xc3 || h.opcode==0xc2) return {h.len,Flow::Return,0};
    if(h.opcode==0xe8 || (h.opcode==0xff && h.modrm_reg==2)) return {h.len,Flow::Call,0};
    if(h.opcode==0xea || h.opcode==0xca || h.opcode==0xcb || h.opcode==0xcf ||
       (h.opcode==0xff && (h.modrm_reg==4 || h.modrm_reg==5))) return {0,Flow::Reject,0};
    const bool jump=h.opcode==0xe9 || h.opcode==0xeb;
    const bool conditional=(h.opcode>=0x70 && h.opcode<=0x7f) ||
        (h.opcode==0x0f && h.opcode2>=0x80 && h.opcode2<=0x8f) ||
        (h.opcode>=0xe0 && h.opcode<=0xe3);
    if(jump || conditional) return {h.len,jump?Flow::Jump:Flow::Conditional,
        h.flags&F_IMM8 ? int32_t(int8_t(h.imm.imm8)) : int32_t(h.imm.imm32)};
    return {h.len,Flow::Next,0};
}
}
