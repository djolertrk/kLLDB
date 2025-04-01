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

TBD
 
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
