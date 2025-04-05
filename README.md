# kLLDB
LLDB based debugger for Linux Kernel

## Install deps

```
echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-19 main" | sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y llvm-19-dev clang-19 libclang-19-dev lld-19 pkg-config libgc-dev libssl-dev zlib1g-dev libcjson-dev libsqlite3-dev libunwind-dev
sudo apt-get install -y python3.12-dev
```

Create symlink to `lldb-19`:

```
cd /usr/bin
sudo ln -S ./lldb ../lib/llvm-19/bin/lldb
```

## Build it

```
mkdir build && cd build
cmake ../kLLDB/ -DCMAKE_BUILD_TYPE=Relase -DLLVM_DIR=/usr/lib/llvm-19/lib/cmake/llvm -GNinja
```

## Examples

`kLLDB` supports both live and offline debugging by parsing `kdump` coredump files.

### Offline debugging - kdump

For the purpose of debugging a `kdump` file, we added an LLDB plugin, that is a wrapper around [libkdumpfile](https://github.com/ptesarik/libkdumpfile).
Lets analyze a crash file from Linux kernel 5.15 and see some `kdump` specific options:

```
$ lldb
(lldb) target create vmlinux
Current executable set to '/path/to/KoviD/kovid/vmlinux' (x86_64).
(lldb) plugin load /path/to/NewKLLDB/build/lib/libkLLDBOffline.so
kLLDBOffline plugin loaded.
kLLDB> kdump open ./crash.file
Opened ./crash.file
kLLDB> kdump info
  Crash File: ./crash.file
  Release: 5.15.0
  Arch: x86_64
  Crash Time: 2025-03-26 08:15:11
  BUILD-ID: 5854168ecc422202ede0880ac960351c37b57faa
  PAGESIZE: 4096
  Crash PID: 260 CPU0
kLLDB> kdump load-lkm kovid.ko
kovid.ko loaded at 0xffffffffc0000000
kLLDB> kdump bugpoint
Instructon pointer at rip=0xffffffffc0003dd5
Blame function: kv_reset_tainted+5
kLLDB> kdump source-dir-map /kovid/ /path/to/KoviD/kovid
Mapped source directory '/kovid/' -> '/path/to/KoviD/kovid'
kLLDB> list kv_reset_tainted
File: /kovid/src/sys.c
   1226 
   1227     if (!within_module(parent_ip, THIS_MODULE))
   1228         regs->ip = (unsigned long)hook->function;
   1229 }
   1230 
   1231 int kv_reset_tainted(unsigned long *tainted_ptr)
   1232 {
   1233     return test_and_clear_bit(TAINT_UNSIGNED_MODULE, tainted_ptr);
   1234 }
   1235 
   1236 #ifdef __x86_64__
   1237 #define _sys_arch(s) "__x64_" s
   1238 #else
   1239 #define _sys_arch(s) s
kLLDB> kdump registers
 CPU: 0, PID: 260
  RAX=0x0000000000000000  RBX=0xFFFFFFFFC000C020  RCX=0x0000000000000000  RDX=0x0000000000000000
  RSI=0xFFFF88807FC17470  RDI=0x0000000000000000  RBP=0xFFFFFFFFC000EB60  RSP=0xFFFFC900000B3DC0
   R8=0xFFFFFFFF82741968   R9=0x00000000FFFFDFFF  R10=0xFFFFFFFF82661980  R11=0xFFFFFFFF82661980
  R12=0xFFFF888005A98100  R13=0x000055C63C7FD45C  R14=0x0000000000000003  R15=0x0000000000000000
  RIP=0xFFFFFFFFC0003DD5  CS=0x0010  EFLAGS=0x00000246  SS=0x0018
  ORIG_RAX=0xFFFFFFFFFFFFFFFF
kLLDB> q
```

### Live debugging

In one terminal, run qemu as:

```
$ qemu-system-x86_64   -kernel "arch/x86/boot/bzImage" -append "root=/dev/sda rw console=ttyS0,115200 nokaslr init=/sbin/init" -drive format=raw,file=/path/to/rootfs.ext2  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22,hostfwd=tcp::9999-:9999 -nographic -s -S
```

In second terminal, run the tool:

```
$ ./bin/kLLDB 
(lldb) command script import ./bin/kLLDB.py
kLLDB plugin initialized successfully.
kLLDB: Plugin loaded from /path/to/build/lib/libkLLDBLive.so
kLLDB: Ready
kLLDB> linux config /path/to/inux-5.15.15/vmlinux
kLLDB: vmlinux path set to: /path/to/linux-5.15.15/vmlinux
kLLDB> linux connect
Failed to connect to GDB stub at 127.0.0.1:1234
Process 1 stopped
* thread #1, stop reason = signal SIGTRAP
    frame #0: 0x000000000000fff0 vmlinux`exception_stacks + 16368
vmlinux`exception_stacks:
->  0xfff0 <+16368>: addb   %al, (%rax)
    0xfff2 <+16370>: addb   %al, (%rax)
    0xfff4 <+16372>: addb   %al, (%rax)
    0xfff6 <+16374>: addb   %al, (%rax)
kLLDB> linux continue
Failed to continue the process.
kLLDB> linux status
Process 1 is running.
kLLDB> linux stop
Process interrupted (like 'process interrupt').
Process 1 stopped
* thread #1, stop reason = signal SIGINT
    frame #0: 0xffffffff8102c57a vmlinux`amd_e400_idle [inlined] amd_e400_idle at process.c:780:3
   777 		 */
   778 		if (!boot_cpu_has_bug(X86_BUG_AMD_APIC_C1E)) {
   779 			default_idle();
-> 780 			return;
   781 		}
   782 	
   783 		tick_broadcast_enter();
kLLDB> bt
* thread #1, stop reason = signal SIGINT
  * frame #0: 0xffffffff8102c57a vmlinux`amd_e400_idle [inlined] amd_e400_idle at process.c:780:3
    frame #1: 0xffffffff8102c56f vmlinux`amd_e400_idle at process.c:771:13
    frame #2: 0xffffffff81c221af vmlinux`default_idle_call at idle.c:112:3
    frame #3: 0xffffffff810a0f44 vmlinux`do_idle [inlined] cpuidle_idle_call at idle.c:194:3
    frame #4: 0xffffffff810a0eec vmlinux`do_idle at idle.c:306:4
    frame #5: 0xffffffff810a1149 vmlinux`cpu_startup_entry(state=CPUHP_ONLINE) at idle.c:403:3
    frame #6: 0xffffffff82d991d7 vmlinux`start_kernel at main.c:1144:2
    frame #7: 0xffffffff81000107 vmlinux`secondary_startup_64 at head_64.S:283
kLLDB> q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] n
kLLDB> list
   784 	
   785 		default_idle();
   786 	
   787 		/*
   788 		 * The switch back from broadcast mode needs to be called with
   789 		 * interrupts disabled.
   790 		 */
kLLDB> q
```

### Using LLM for bug report

Download LLM:

```
$ wget https://huggingface.co/lmstudio-community/DeepSeek-R1-Distill-Llama-8B-GGUF/resolve/main/DeepSeek-R1-Distill-Llama-8B-Q8_0.gguf
```

Download packages:

```
$ python3 -m venv kdump-venv
$ source kdump-venv/bin/activate
$ pip3 install pexpect llama-cpp-python
```

There is a Python script that uses local LLM that parses `kLLDB` analysis for bug reporting.
You can use it this way:

```

(kdump-venv) $ kLLDB/scripts/report-linux-bug.py --llm-path  /path/to/DeepSeek-R1-Distill-Llama-8B-Q8_0.gguf --lldb-path /usr/bin/lldb --kdump-plugin-path /path/to/libkLLDBOffline.so --vmlinux-path vmlinux --crash-file-path ./crash.file --lkm-path /path/to/lkm.ko --source-dir-old /remote-dir/ --source-dir-new /path-to-local-dir/ --report-file=bug-report-32.txt
$ cat bug-report-32.txt 
kLLDB sesion:
(lldb) target create vmlinux
Current executable set to '/path/to/KoviD/kovid/vmlinux' (x86_64).
(lldb) plugin load /path/to/NewKLLDB/build/lib/libkLLDBOffline.so
kLLDBOffline plugin loaded.
kLLDB> kdump open ./crash.file
Opened ./crash.file
kLLDB> kdump info
  Crash File: ./crash.file
  Release: 5.15.0
  Arch: x86_64
  Crash Time: 2025-03-26 08:15:11
  BUILD-ID: 5854168ecc422202ede0880ac960351c37b57faa
  PAGESIZE: 4096
  Crash PID: 260 CPU0
kLLDB> kdump load-lkm kovid.ko
kovid.ko loaded at 0xffffffffc0000000
kLLDB> kdump bugpoint
Instructon pointer at rip=0xffffffffc0003dd5
Blame function: kv_reset_tainted+5
kLLDB> kdump source-dir-map /kovid/ /path/to/KoviD/kovid
Mapped source directory '/kovid/' -> '/path/to/KoviD/kovid'
kLLDB> list kv_reset_tainted
File: /kovid/src/sys.c
   1226 
   1227     if (!within_module(parent_ip, THIS_MODULE))
   1228         regs->ip = (unsigned long)hook->function;
   1229 }
   1230 
   1231 int kv_reset_tainted(unsigned long *tainted_ptr)
   1232 {
   1233     return test_and_clear_bit(TAINT_UNSIGNED_MODULE, tainted_ptr);
   1234 }
   1235 
   1236 #ifdef __x86_64__
   1237 #define _sys_arch(s) "__x64_" s
   1238 #else
   1239 #define _sys_arch(s) s
kLLDB> kdump registers
 CPU: 0, PID: 260
  RAX=0x0000000000000000  RBX=0xFFFFFFFFC000C020  RCX=0x0000000000000000  RDX=0x0000000000000000
  RSI=0xFFFF88807FC17470  RDI=0x0000000000000000  RBP=0xFFFFFFFFC000EB60  RSP=0xFFFFC900000B3DC0
   R8=0xFFFFFFFF82741968   R9=0x00000000FFFFDFFF  R10=0xFFFFFFFF82661980  R11=0xFFFFFFFF82661980
  R12=0xFFFF888005A98100  R13=0x000055C63C7FD45C  R14=0x0000000000000003  R15=0x0000000000000000
  RIP=0xFFFFFFFFC0003DD5  CS=0x0010  EFLAGS=0x00000246  SS=0x0018
  ORIG_RAX=0xFFFFFFFFFFFFFFFF
kLLDB> q
Blame module: kovid.ko

=====

LLM report:
Alright, I'm trying to figure out why the Linux kernel is crashing with the given details. Let's start by looking at the information provided.

The crash is happening in the `kv_reset_tainted` function, specifically at an instruction pointer `0xffffffffc0003dd5`. The function is part of the `kovid.ko` module. The register dump shows that `RIP` is pointing to this function, so the crash is definitely happening inside `kv_reset_tainted`.

Looking at the function definition in `sys.c`, `kv_reset_tainted` takes a single argument `tainted_ptr`, which is a pointer to an unsigned long. The function uses `test_and_clear_bit` with `TAINT_UNSIGNED_MODULE` and `tainted_ptr` as arguments. 

In the register dump, the registers are in a state that might indicate an error. The `RAX` is zero, which might mean that the function isn't returning properly or there's an issue with the return value. The `RBX` has a value of `0xFFFFFFFFC000C020`, which is a 64-bit address, but I'm not sure if that's relevant here.

I notice that the function is called with a pointer, but in the register dump, `RDI` (the first argument) is zero. That's odd because `RDI` is the destination for the first argument of a function. If `tainted_ptr` is being passed as zero, that could cause issues because the function expects a valid pointer.

So, the likely cause is that `kv_reset_tainted` is being called with a null or invalid `tainted_ptr` argument. This might be due to a bug in the calling code that's not passing the correct pointer, or perhaps a null pointer dereference within the function itself.

To debug this, I should check how `kv_reset_tainted` is being called. If it's being called with a null pointer, that's a problem. Also, I should look into the context where `tainted_ptr` is being set to ensure it's not null before calling the function.

Another angle is to examine the `test_and_clear_bit` function to see if it's handling the `tainted_ptr` correctly, especially if it's not a valid pointer. Maybe there's a missing bounds check or a null pointer check that's causing the crash.

In summary, the crash is due to a null or invalid pointer being passed to `kv_reset_tainted`, leading to an issue
=====
```
