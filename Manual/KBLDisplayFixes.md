# SKL/KBL display fixes

These fixes target two display problems on laptops with Intel Skylake/Kaby Lake
integrated graphics. Choose the option that matches the symptom:

- **Internal screen stays black after reopening the lid — `igfxhpdafix=1`:**
  with an external display connected, closing and reopening the lid leaves the
  built-in screen black while the external display keeps working. Unplugging the
  external display or clicking **Detect Displays** brings the built-in screen back.
- **External screen goes black after startup — `igfxcdclkfix=1`:** after starting
  macOS, the external display briefly shows a picture, then goes black or reports
  **No Signal**. The same display works after the laptop fully sleeps and wakes.

Enable both options if both problems occur.

## How it works

The implementation requires SKL/KBL display hardware and the loaded
`AppleIntelKBLGraphicsFramebuffer` driver. The following checks are performed
by the patch before it applies a change.

**HPD-A** finds one matching original or already-patched instruction sequence in
`hwEnableInterrupts`. It enables HPD-A detection by setting bit 28 in the existing
OR instruction for register `0xC4030`.

**CDCLK** checks that the native functions match the bundled ABI signatures. The
initial modeset must have one active port-A eDP path, no active external pipelines,
an 8.1 GHz DPLL0 VCO, fixed clock policy, and no TCON path. Clock/cache values,
fuse limits, power state, and mailbox state must pass validation.

The display engine is reinitialized when the current clock is below its native
target:

| Native CDCLK target | Eligible current clocks |
| --- | --- |
| 675 MHz | 337.5, 450, 540 MHz |
| 540 MHz | 337.5, 450 MHz |

It performs one transaction during initial modesetting, under the native
controller lock:

`DisableDisplay` → verify outputs stopped → `uninitDisplayEngine` → verify
PLL/DBUF off → `initDisplayEngine` → verify target clock → complete `hwSetMode`.

The sequence uses native Apple methods and temporarily forces a complete modeset
through WEG's existing FCM hook. Outside this transaction, the existing
`igfxfcms` / `igfxfcmsfbs` behavior is preserved.

## Usage

Append either or both independent options to `boot-args`:

```text
igfxhpdafix=1 igfxcdclkfix=1
```

Both are disabled by default. Only `=1` enables a fix; `=0` or omitting the option
keeps it disabled.

## Debug

Use the **Debug** build of WhateverGreen, append `-wegdbg` alongside the desired
feature options, and reboot:

```text
igfxhpdafix=1 igfxcdclkfix=1 -wegdbg
```

Check the active arguments and IGPU diagnostic properties:

```sh
sysctl -n kern.bootargs
ioreg -r -n IGPU -d1 -l -w0 | grep -E '"KBL(DisplayFix|CDCLK|HPDA)'
```

- `KBLHPDAStatus`: `applied-verified` means the instruction change was verified;
  `already-present` means it was already applied.
- `KBLCDCLKStatus`: `applied-native-target` means native initialization reached
  the target and the following modeset succeeded. Other values identify the
  waiting, skipped, or failed stage.
- `KBLCDCLK*` snapshots (`Before`, `Stopped`, `EngineOff`, `Initialized`, `After`)
  record clock, cache, power, and pipeline state at each stage.
