#pragma once
#include <Headers/kern_patcher.hpp>
#include <Headers/kern_devinfo.hpp>
namespace KBLDisplay {
void select(DeviceInfo *);
void deinit();
bool hpdRequested();
bool cdclkRequested();
void applyHPD(KernelPatcher &,size_t,mach_vm_address_t,size_t,KernelPatcher::KextInfo *);
bool prepare(KernelPatcher &,size_t,mach_vm_address_t,size_t);
void install(KernelPatcher &,size_t,mach_vm_address_t,size_t);
void modesetRouteReady(bool);
bool forceModeUpdate(void *,void *);
}
