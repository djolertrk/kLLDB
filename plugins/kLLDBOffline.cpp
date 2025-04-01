//
// kLLDB - offline deubg of kdump crash files
// by djolertrk
//

#include <lldb/API/LLDB.h>
#include <lldb/API/SBAddress.h>
#include <lldb/API/SBBlock.h>
#include <lldb/API/SBCommandInterpreter.h>
#include <lldb/API/SBCommandReturnObject.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/API/SBError.h>
#include <lldb/API/SBFileSpec.h>
#include <lldb/API/SBModule.h>
#include <lldb/API/SBSection.h>
#include <lldb/API/SBSymbol.h>
#include <lldb/API/SBSymbolContext.h>
#include <lldb/API/SBTarget.h>

#include <llvm/Object/Binary.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/SymbolSize.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <libkdumpfile/kdumpfile.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vector>

struct X86_64_Regs {
  uint64_t r15, r14, r13, r12;
  uint64_t rbp, rbx, r11, r10;
  uint64_t r9, r8, rax, rcx;
  uint64_t rdx, rsi, rdi, orig_rax;
  uint64_t rip, cs, eflags, rsp, ss;

  X86_64_Regs() { ::memset(this, 0, sizeof(*this)); }
};

struct ThreadInfo {
  uint64_t tid; // from "cpu.#.pid"
  X86_64_Regs regs;

  std::string comm;     // from "cpu.#.comm" (if available)
  uint64_t task;        // from "cpu.#.task" (if available)
  uint64_t thread_info; // from "cpu.#.thread_info" (if available)
  uint64_t cpu_index;   // to keep track of CPU # (optional)
};

// TODO: For targets other than x86_64, this needs to be fixed.
#define ELF_NGREG 27
struct timeval_64 {
  int64_t tv_sec;
  int64_t tv_usec;
} __attribute__((packed));

struct elf_prstatus {
  struct {
    int32_t si_signo;
    int32_t si_code;
    int32_t si_errno;
  } __attribute__((packed)) pr_info;
  int16_t pr_cursig;
  char _pad1[2];
  uint64_t pr_sigpend;
  uint64_t pr_sighold;
  int32_t pr_pid;
  int32_t pr_ppid;
  int32_t pr_pgrp;
  int32_t pr_sid;
  struct timeval_64 pr_utime;
  struct timeval_64 pr_stime;
  struct timeval_64 pr_cutime;
  struct timeval_64 pr_cstime;
  uint64_t pr_reg[ELF_NGREG];
} __attribute__((packed));

struct _kdump_blob {
  /** Reference counter. */
  unsigned long refcnt;

  /** Pin counter. */
  unsigned long pincnt;

  void *data;  /**< Binary data. */
  size_t size; /**< Size of binary data. */
};

//--------------------------------------------------------------------------------------
// KdumpBackend: uses libkdumpfile for reading a kdump
//--------------------------------------------------------------------------------------

class KdumpBackend {
public:
  KdumpBackend() : m_ctx(nullptr), m_is_open(false) {}

  ~KdumpBackend() { Close(); }

  bool Open(const std::string &path) {
    Close();

    m_ctx = kdump_new();
    if (!m_ctx) {
      m_err = "kdump_new() failed";
      return false;
    }

    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
      m_err = "Cannot open file: " + path;
      kdump_free(m_ctx);
      m_ctx = nullptr;
      return false;
    }

    kdump_status st = kdump_open_fd(m_ctx, fd);
    ::close(fd);
    if (st != KDUMP_OK) {
      m_err = std::string("kdump_open_fd() failed: ") + kdump_get_err(m_ctx);
      kdump_free(m_ctx);
      m_ctx = nullptr;
      return false;
    }

    ParseCpus();
    m_is_open = true;
    return true;
  }

  void Close() {
    if (m_ctx) {
      kdump_free(m_ctx);
      m_ctx = nullptr;
    }
    m_threads.clear();
    m_is_open = false;
  }

  bool IsOpen() const { return m_is_open; }

  std::string GetError() const { return m_err; }

  const std::vector<ThreadInfo> &GetThreads() const { return m_threads; }

  // A minimal read from kernel VA
  bool ReadMemory(uint64_t va, void *buf, size_t size) {
    if (!m_ctx) {
      return false;
    }

    uint8_t *dst = static_cast<uint8_t *>(buf);
    size_t done = 0;
    while (done < size) {
      size_t chunk = size - done;
      size_t got = chunk;
      kdump_status s = kdump_read(m_ctx, KDUMP_KVADDR,
                                  (kdump_addr_t)(va + done), dst + done, &got);
      if (s != KDUMP_OK || got == 0) {
        // zero fill remainder
        ::memset(dst + done, 0, chunk);
        return false;
      }
      done += got;
    }
    return true;
  }

  // read a top-level attribute
  std::string GetAttrString(const std::string &path) {
    if (!m_ctx)
      return "";
    kdump_attr_ref_t ref;
    if (kdump_attr_ref(m_ctx, path.c_str(), &ref) != KDUMP_OK)
      return "";

    kdump_attr_t a;
    if (kdump_attr_ref_get(m_ctx, &ref, &a) != KDUMP_OK) {
      kdump_attr_unref(m_ctx, &ref);
      return "";
    }

    std::string result;
    if (a.type == KDUMP_STRING && a.val.string) {
      result = a.val.string;
    } else if (a.type == KDUMP_NUMBER) {
      char tmp[64];
      ::snprintf(tmp, sizeof(tmp), "%" PRIu64, a.val.number);
      result = tmp;
    }

    kdump_attr_discard(m_ctx, &a);
    kdump_attr_unref(m_ctx, &ref);
    return result;
  }

private:
  // Read process/thread data from "cpu".
  void ParseCpus() {
    if (!m_ctx)
      return;

    // Get a reference to the "cpu" attribute
    kdump_attr_ref_t cpuRef;
    if (kdump_attr_ref(m_ctx, "cpu", &cpuRef) != KDUMP_OK)
      return;

    // Start iteration over all cpu.<N> subkeys
    kdump_attr_iter_t it;
    if (kdump_attr_ref_iter_start(m_ctx, &cpuRef, &it) != KDUMP_OK) {
      kdump_attr_unref(m_ctx, &cpuRef);
      return;
    }

    while (it.key) {
      ThreadInfo thr;
      std::memset(&thr, 0, sizeof(thr));

      // (1) CPU index from "cpu.<key>"
      thr.cpu_index = strtoull(it.key, nullptr, 10); // e.g. "0"

      // (2) TID from "cpu.#.pid"
      {
        std::string ppath = std::string("cpu.") + it.key + ".pid";
        kdump_attr_ref_t pRef;
        if (kdump_attr_ref(m_ctx, ppath.c_str(), &pRef) == KDUMP_OK) {
          kdump_attr_t a;
          if (kdump_attr_ref_get(m_ctx, &pRef, &a) == KDUMP_OK) {
            if (a.type == KDUMP_NUMBER) {
              thr.tid = a.val.number;
            }
            kdump_attr_discard(m_ctx, &a);
          }
          kdump_attr_unref(m_ctx, &pRef);
        }
      }

      // We can do:
      // thr.regs.rip = ReadReg(it.key, "rip");
      // thr.regs.rbp = ReadReg(it.key, "rbp");
      // etc. but will do prstatus parse.

      // Now parse PRSTATUS for the *full* register set, if present
      {
        std::string prPath = std::string("cpu.") + it.key + ".PRSTATUS";
        kdump_attr_ref_t prRef;
        if (kdump_attr_ref(m_ctx, prPath.c_str(), &prRef) == KDUMP_OK) {
          kdump_attr_t prAtt;
          if (kdump_attr_ref_get(m_ctx, &prRef, &prAtt) == KDUMP_OK) {
            // Check for KDUMP_BLOB type, then the size
            if (prAtt.type == KDUMP_BLOB && prAtt.val.blob) {
              size_t sz = prAtt.val.blob->size;
              if (sz >= sizeof(elf_prstatus)) {
                elf_prstatus prs;
                std::memcpy(&prs, prAtt.val.blob->data, sizeof(prs));

                // Overwrite tid from pr_pid
                thr.tid = prs.pr_pid;

                // x86_64 pr_reg[]: 0=R15,1=R14,2=R13,3=R12,4=RBP,5=RBX,...
                thr.regs.r15 = prs.pr_reg[0];
                thr.regs.r14 = prs.pr_reg[1];
                thr.regs.r13 = prs.pr_reg[2];
                thr.regs.r12 = prs.pr_reg[3];
                thr.regs.rbp = prs.pr_reg[4];
                thr.regs.rbx = prs.pr_reg[5];
                thr.regs.r11 = prs.pr_reg[6];
                thr.regs.r10 = prs.pr_reg[7];
                thr.regs.r9 = prs.pr_reg[8];
                thr.regs.r8 = prs.pr_reg[9];
                thr.regs.rax = prs.pr_reg[10];
                thr.regs.rcx = prs.pr_reg[11];
                thr.regs.rdx = prs.pr_reg[12];
                thr.regs.rsi = prs.pr_reg[13];
                thr.regs.rdi = prs.pr_reg[14];
                thr.regs.orig_rax = prs.pr_reg[15];
                thr.regs.rip = prs.pr_reg[16];
                thr.regs.cs = prs.pr_reg[17];
                thr.regs.eflags = prs.pr_reg[18];
                thr.regs.rsp = prs.pr_reg[19];
                thr.regs.ss = prs.pr_reg[20];
                // TODO: parse fs_base, gs_base, ds, es, fs, gs etc.
              }
            }
            kdump_attr_discard(m_ctx, &prAtt);
          }
          kdump_attr_unref(m_ctx, &prRef);
        }
      }

      // push the thread in the vector
      m_threads.push_back(thr);

      // iterate next CPU
      if (kdump_attr_iter_next(m_ctx, &it) != KDUMP_OK) {
        break;
      }
    }

    kdump_attr_iter_end(m_ctx, &it);
    kdump_attr_unref(m_ctx, &cpuRef);
  }

  uint64_t ReadReg(const std::string &cpuKey, const std::string &regName) {
    std::string path = "cpu." + cpuKey + ".reg." + regName;
    kdump_attr_ref_t ref;
    if (kdump_attr_ref(m_ctx, path.c_str(), &ref) != KDUMP_OK) {
      return 0;
    }
    kdump_attr_t a;
    if (kdump_attr_ref_get(m_ctx, &ref, &a) != KDUMP_OK) {
      kdump_attr_unref(m_ctx, &ref);
      return 0;
    }
    uint64_t val = 0;
    if (a.type == KDUMP_NUMBER) {
      val = a.val.number;
    }
    kdump_attr_discard(m_ctx, &a);
    kdump_attr_unref(m_ctx, &ref);
    return val;
  }

private:
  kdump_ctx_t *m_ctx;
  bool m_is_open;
  std::string m_err;
  std::vector<ThreadInfo> m_threads;
};

static KdumpBackend g_kdump;
static std::string g_coreFilePath;

static bool SafeReadU64(uint64_t va, uint64_t &val) {
  val = 0;
  uint8_t tmp[8];
  if (!g_kdump.ReadMemory(va, tmp, sizeof(tmp))) {
    return false;
  }
  val = *(const uint64_t *)(tmp);
  return true;
}

struct Frame {
  uint64_t rip;
  uint64_t rbp;
};

static std::vector<Frame> WalkStack_RBP(uint64_t rip, uint64_t rbp) {
  std::vector<Frame> frames;
  frames.reserve(64);

  frames.push_back({rip, rbp});

  for (int i = 0; i < 63; i++) {
    uint64_t nrip = 0, nrbp = 0;
    if (!SafeReadU64(rbp, nrbp))
      break;
    if (!SafeReadU64(rbp + 8, nrip))
      break;
    if (nrbp <= rbp)
      break;
    if (nrip < 0xffffffff80000000ULL)
      break;

    frames.push_back({nrip, nrbp});
    rbp = nrbp;
  }
  return frames;
}

//--------------------------------------------------------------------------------------
// Commands
//--------------------------------------------------------------------------------------

// TODO: Check Linux 6.x
class CoreLoadLKMCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger dbg, char **cmd,
                 lldb::SBCommandReturnObject &res) override {
    // Check if we have a valid dump file loaded
    if (!g_kdump.IsOpen()) {
      res.AppendMessage("No open kdump. 'kdump open <crash file>' first.");
      return false;
    }

    // Ensure the user has provided the .ko path
    if (!cmd || !cmd[0]) {
      res.AppendMessage("Usage: kdump load-lkm <module-path.ko>");
      return false;
    }

    // Retrieve the kernel release from the kdump. (e.g.
    // "5.15.0-051500-generic")
    std::string release = g_kdump.GetAttrString("linux.uts.release");
    if (release.empty()) {
      res.AppendMessage(
          "Warning: kernel version (linux.uts.release) not found. "
          "The default LKM load address may be incorrect!");
    } else {
      // Simple check: if "5.15." is not present, warn the user
      if (release.find("5.15.") == std::string::npos) {
        std::ostringstream warn;
        warn << "Warning: kernel version is '" << release
             << "', which is NOT 5.15.x. The default LKM load address "
                "(0xffffffffc0000000) may be incorrect!";
        res.AppendMessage(warn.str().c_str());
      }
    }

    static bool lkm_loaded = false;
    if (lkm_loaded) {
      // Already loaded once this session
      res.AppendMessage("LKM already loaded, ignoring.");
      return true;
    }

    std::string lkmPath = cmd[0];

    // Ensure we have a valid target (the user presumably has done "target
    // create vmlinux")
    lldb::SBTarget target = dbg.GetSelectedTarget();
    if (!target.IsValid()) {
      res.AppendMessage(
          "No valid target. Use 'target create vmlinux' or 'kdump open'.");
      return false;
    }

    // Actually load the module at slide 0xffffffffc0000000
    // 1) Add the image
    {
      std::ostringstream oss;
      oss << "image add " << lkmPath;
      dbg.HandleCommand(oss.str().c_str());
    }

    // 2) Then load with --slide
    {
      std::ostringstream oss;
      oss << "image load --file " << lkmPath << " --slide 0xffffffffc0000000";
      dbg.HandleCommand(oss.str().c_str());
    }

    // Mark as loaded
    lkm_loaded = true;

    // Success message
    std::ostringstream msg;
    msg << lkmPath << " loaded at 0xffffffffc0000000";
    res.AppendMessage(msg.str().c_str());

    return true;
  }
};

class CoreSourceDirMapCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger dbg, char **cmd,
                 lldb::SBCommandReturnObject &res) override {
    // Basic usage check
    if (!cmd || !cmd[0] || !cmd[1]) {
      res.AppendMessage("Usage: kdump source-dir-map <fromDir> <toDir>");
      return false;
    }

    std::string fromDir = cmd[0];
    std::string toDir = cmd[1];

    // We assume a valid target is open, but it's not strictly required to do
    // source mapping.
    lldb::SBTarget target = dbg.GetSelectedTarget();
    if (!target.IsValid()) {
      res.AppendMessage("Warning: No valid target. Mapping anyway.");
    }

    // Build and execute the actual LLDB command:
    //  settings set target.source-map <fromDir> <toDir>
    std::ostringstream oss;
    oss << "settings set target.source-map " << fromDir << " " << toDir;

    dbg.HandleCommand(oss.str().c_str());

    // Confirm success
    std::ostringstream msg;
    msg << "Mapped source directory '" << fromDir << "' -> '" << toDir << "'";
    res.AppendMessage(msg.str().c_str());

    return true;
  }
};

// TODO: Fix this for other kernels e.g. 6.x
static constexpr uint64_t MODULE_BASE = 0xffffffffc0000000;

// Helper to find the "best" symbol for an offset.
// Returns (symbolName, offsetInSymbol).
static std::pair<std::string, uint64_t>
FindSymbolInModule(llvm::StringRef koPath, uint64_t moduleOffset) {
  namespace obj = llvm::object;

  // Prepare return values (if fail, return something plausible)
  std::string bestName = "<unknown>";
  uint64_t offsetIntoSym = moduleOffset;

  // Load the .ko file into memory
  auto binOrErr = obj::createBinary(koPath);
  if (!binOrErr) {
    // In real code, you should log or print
    // llvm::toString(binOrErr.takeError())
    return {bestName, offsetIntoSym};
  }

  // We expect a valid object file
  obj::Binary &bin = *binOrErr.get().getBinary();
  auto *objFile = llvm::dyn_cast<obj::ObjectFile>(&bin);
  if (!objFile) {
    return {bestName, offsetIntoSym};
  }

  // We will find the symbol whose "Value" is <= moduleOffset,
  // and is the largest such Value (i.e. the nearest preceding symbol).
  // E.g. if offset is 0x3dd5, we want the symbol that starts at or before
  // 0x3dd5.
  uint64_t bestSymAddr = 0;
  for (auto sym : objFile->symbols()) {
    // Symbol must be in the .text or other relevant section (STT_FUNC).
    // We can check type or flags if desired:
    auto symType = sym.getType();
    if (!symType) // if error
      continue;
    if (*symType != obj::SymbolRef::ST_Function &&
        *symType != obj::SymbolRef::ST_Data &&
        *symType != obj::SymbolRef::ST_Unknown) {
      // For kernel modules, sometimes STT_NOTYPE is used; we can relax checks
      continue;
    }

    // Get symbol address (Value)
    llvm::Expected<uint64_t> addrOrErr = sym.getValue();
    if (!addrOrErr)
      continue;
    uint64_t symAddr = *addrOrErr; // offset within the module file

    // If symbol name is not available, skip
    llvm::Expected<llvm::StringRef> nameOrErr = sym.getName();
    if (!nameOrErr)
      continue;
    llvm::StringRef symName = *nameOrErr;
    if (symName.empty())
      continue;

    // We want the symbol that starts <= moduleOffset, but is closest
    if (symAddr <= moduleOffset && symAddr >= bestSymAddr) {
      bestSymAddr = symAddr;
      bestName = symName.str();
    }
  }

  // The offset within that symbol is (moduleOffset - bestSymAddr)
  offsetIntoSym = moduleOffset - bestSymAddr;
  return {bestName, offsetIntoSym};
}

/// A helper to get the path from an SBFileSpec in a portable way
static std::string GetFileSpecPath(const lldb::SBFileSpec &fspec) {
  if (!fspec.IsValid())
    return std::string();
  char path_buf[1024];
  uint32_t len = fspec.GetPath(path_buf, sizeof(path_buf));
  if (len == 0)
    return std::string();
  return std::string(path_buf);
}

static bool FindModuleForAddress(lldb::SBTarget &target, uint64_t rip,
                                 std::string &outModulePath) {
  uint32_t numMods = target.GetNumModules();
  for (uint32_t i = 0; i < numMods; ++i) {
    lldb::SBModule mod = target.GetModuleAtIndex(i);
    if (!mod.IsValid())
      continue;

    uint32_t numSecs = mod.GetNumSections();
    for (uint32_t s = 0; s < numSecs; ++s) {
      lldb::SBSection sec = mod.GetSectionAtIndex(s);
      if (!sec.IsValid())
        continue;

      // The load address is fetched from the section object, not from the
      // target
      uint64_t secLoadAddr = sec.GetLoadAddress(target);
      uint64_t secSize = sec.GetByteSize();
      if (secLoadAddr == LLDB_INVALID_ADDRESS)
        continue;

      // Check if rip lies within [secLoadAddr, secLoadAddr+secSize)
      if (rip >= secLoadAddr && rip < (secLoadAddr + secSize)) {
        lldb::SBFileSpec fspec = mod.GetFileSpec();
        std::string dir(fspec.GetDirectory());
        std::string fname(fspec.GetFilename());
        if (!dir.empty()) {
          outModulePath = dir + "/" + fname;
        } else {
          outModulePath = fname;
        }
        return true;
      }
    }
  }
  return false; // not found
}

class CoreBugpointCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger dbg, char **cmd,
                 lldb::SBCommandReturnObject &res) override {
    // Ensure we have a valid kdump
    if (!g_kdump.IsOpen()) {
      res.AppendMessage("No open kdump. 'kdump open <crash file>' first.");
      return false;
    }

    lldb::SBTarget target = dbg.GetSelectedTarget();
    if (!target.IsValid()) {
      res.AppendMessage("No valid target - 'target create vmlinux' maybe?");
      return false;
    }

    // Pick CPU #0 / first thread
    auto &threads = g_kdump.GetThreads();
    if (threads.empty()) {
      res.AppendMessage("No threads in dump!");
      return false;
    }

    const auto &r = threads[0].regs;
    uint64_t rip = r.rip;
    uint64_t rbp = r.rbp;

    // Perform naive RBP-based backtrace
    auto frames = WalkStack_RBP(rip, rbp);

    // Now for each frame, we compute offset from module base
    // and parse the .ko to find the function symbol
    for (size_t i = 0; i < frames.size(); i++) {
      // Print the raw RIP/RBP
      char line[256];
      // ::snprintf(line, sizeof(line),
      //            "#%zu  rip=0x%016" PRIx64 "  rbp=0x%016" PRIx64,
      //            i, frames[i].rip, frames[i].rbp);
      ::snprintf(line, sizeof(line),
                 "Instructon pointer at rip=0x%016" PRIx64 "", frames[i].rip);
      res.AppendMessage(line);

      std::string blameModulePath;
      uint64_t offset = frames[i].rip;
      if (!FindModuleForAddress(target, offset, blameModulePath)) {
        char err_line[128];
        ::snprintf(err_line, sizeof(err_line),
                   "Unable to find loaded module with address 0x%016" PRIx64 "",
                   frames[i].rip);
        res.AppendMessage(err_line);
        return false;
      }

      std::ostringstream oss;
      if (!blameModulePath.empty()) {
        llvm::outs() << "Blame module: " << blameModulePath << "\n";
        res.AppendMessage(oss.str().c_str());
      }

      // If the RIP is in range for our lkm ko, let's parse that .ko file
      // This is just a check if rip >= MODULE_BASE, < MODULE_BASE +
      // (size?) Let's do a simple check if it's >= base (and < base+someMax).
      // For a real check, you might parse sections to see actual .text size.
      // Otherwise we assume the address is good - from vmlinux.
      if (frames[i].rip >= MODULE_BASE &&
          frames[i].rip < (MODULE_BASE + 0x100000)) {
        offset = frames[i].rip - MODULE_BASE;
      }

      // Manually parse the .ko symbol table
      auto sym = FindSymbolInModule(blameModulePath, offset);
      if (!sym.first.empty()) {
        // If we found a symbol, print it
        oss << "Blame function: " << sym.first;
        if (sym.second) {
          oss << "+" << sym.second;
        }
        res.AppendMessage(oss.str().c_str());
      }
    }

    return true;
  }
};

class CoreInfoCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger dbg, char **cmd,
                 lldb::SBCommandReturnObject &res) override {
    if (!g_kdump.IsOpen()) {
      res.AppendMessage("No open kdump for 'info'");
      return false;
    }
    // example: read some stuff
    std::string release = g_kdump.GetAttrString("linux.uts.release");
    std::string arch = g_kdump.GetAttrString("arch.name");
    std::string ctime =
        g_kdump.GetAttrString("linux.vmcoreinfo.lines.CRASHTIME");
    std::string buildid =
        g_kdump.GetAttrString("linux.vmcoreinfo.lines.BUILD-ID");
    std::string pagesize =
        g_kdump.GetAttrString("linux.vmcoreinfo.lines.PAGESIZE");

    std::string timestr = "(none)";
    if (!ctime.empty()) {
      unsigned long long epoch = 0ULL;
      ::sscanf(ctime.c_str(), "%llu", &epoch);
      if (epoch != 0ULL) {
        time_t rawt = (time_t)epoch;
        struct tm tmpbuf;
        if (localtime_r(&rawt, &tmpbuf)) {
          char tbuf[64];
          ::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tmpbuf);
          timestr = tbuf;
        }
      }
    }

    std::ostringstream oss;
    oss << "  Crash File: " << g_coreFilePath << "\n"
        << "  Release: " << release << "\n"
        << "  Arch: " << arch << "\n"
        << "  Crash Time: " << timestr << "\n"
        << "  BUILD-ID: " << buildid << "\n"
        << "  PAGESIZE: " << pagesize << "\n";

    auto &threads = g_kdump.GetThreads();
    for (size_t i = 0; i < threads.size(); i++) {
      const ThreadInfo &th = threads[i];
      // skip PID == 0.
      if (th.tid == 0)
        continue;

      oss << "  Crash PID: " << th.tid << " CPU" << th.cpu_index << '\n';
    }

    res.AppendMessage(oss.str().c_str());
    return true;
  }
};

class CoreRegistersCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger dbg, char **cmd,
                 lldb::SBCommandReturnObject &res) override {
    if (!g_kdump.IsOpen()) {
      res.AppendMessage("No open kdump for 'info'");
      return false;
    }

    std::ostringstream oss;
    auto &threads = g_kdump.GetThreads();
    for (size_t i = 0; i < threads.size(); i++) {
      const ThreadInfo &th = threads[i];
      // skip PID == 0.
      if (th.tid == 0)
        continue;
      // Print a header line about the thread/cpu
      oss << " CPU: " << th.cpu_index << ", PID: " << th.tid << "\n";

      // Switch to hex, uppercase, with zero padding if desired
      oss << std::uppercase << std::hex << std::setfill('0');

      // First line: RAX, RBX, RCX, RDX
      oss << "  RAX=0x" << std::setw(16) << th.regs.rax << "  RBX=0x"
          << std::setw(16) << th.regs.rbx << "  RCX=0x" << std::setw(16)
          << th.regs.rcx << "  RDX=0x" << std::setw(16) << th.regs.rdx << "\n";

      // Second line: RSI, RDI, RBP, RSP
      oss << "  RSI=0x" << std::setw(16) << th.regs.rsi << "  RDI=0x"
          << std::setw(16) << th.regs.rdi << "  RBP=0x" << std::setw(16)
          << th.regs.rbp << "  RSP=0x" << std::setw(16) << th.regs.rsp << "\n";

      // Third line: R8, R9, R10, R11
      oss << "   R8=0x" << std::setw(16) << th.regs.r8 << "   R9=0x"
          << std::setw(16) << th.regs.r9 << "  R10=0x" << std::setw(16)
          << th.regs.r10 << "  R11=0x" << std::setw(16) << th.regs.r11 << "\n";

      // Fourth line: R12, R13, R14, R15
      oss << "  R12=0x" << std::setw(16) << th.regs.r12 << "  R13=0x"
          << std::setw(16) << th.regs.r13 << "  R14=0x" << std::setw(16)
          << th.regs.r14 << "  R15=0x" << std::setw(16) << th.regs.r15 << "\n";

      // Next line: RIP, CS, EFLAGS, SS, ORIG_RAX
      // (cs and ss are 16-bit, eflags might be 32 bits, but we can show them in
      // hex)
      oss << "  RIP=0x" << std::setw(16) << th.regs.rip << "  CS=0x"
          << std::setw(4) << (uint16_t)th.regs.cs << "  EFLAGS=0x"
          << std::setw(8) << (uint32_t)th.regs.eflags << "  SS=0x"
          << std::setw(4) << (uint16_t)th.regs.ss << "\n";

      oss << "  ORIG_RAX=0x" << std::setw(16) << th.regs.orig_rax << "\n\n";

      // restore default formatting
      oss << std::dec << std::nouppercase;
    }

    res.AppendMessage(oss.str().c_str());
    return true;
  }
};

class CoreOpenCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger dbg, char **cmd,
                 lldb::SBCommandReturnObject &res) override {
    if (!cmd || !cmd[0]) {
      res.AppendMessage("Usage: kdump open <crash file>");
      return false;
    }

    std::string vmcorePath = cmd[0];
    std::string vmlinuxPath;
    if (cmd[1]) {
      vmlinuxPath = cmd[1];
    }

    // close old
    g_kdump.Close();
    g_coreFilePath = vmcorePath;

    if (!g_kdump.Open(vmcorePath)) {
      std::string e = "Failed to open: ";
      e += vmcorePath + " => " + g_kdump.GetError();
      res.AppendMessage(e.c_str());
      return false;
    }

    lldb::SBTarget target = dbg.GetSelectedTarget();
    if (!vmlinuxPath.empty()) {
      lldb::SBError err;
      target = dbg.CreateTarget(vmlinuxPath.c_str(), "", "", true, err);
      if (err.Fail()) {
        std::string e = "Failed to load vmlinux: ";
        e += err.GetCString();
        res.AppendMessage(e.c_str());
      } else {
        // optional: read "phys_base" from kdump attr
        auto physb_str =
            g_kdump.GetAttrString("linux.vmcoreinfo.NUMBER.phys_base");
        if (!physb_str.empty()) {
          uint64_t pb = strtoull(physb_str.c_str(), nullptr, 0);
          if (pb) {
            // set section load address, etc.
            lldb::SBModule mod = target.GetModuleAtIndex(0);
            if (mod.IsValid()) {
              lldb::SBSection s_text = mod.FindSection("__text");
              if (s_text.IsValid()) {
                lldb::SBError e2 = target.SetSectionLoadAddress(s_text, pb);
                if (e2.Fail()) {
                  std::string w = "Could not set load address: ";
                  w += e2.GetCString();
                  res.AppendMessage(w.c_str());
                }
              }
            }
          }
        }
      }
    }

    char msg[256];
    ::snprintf(msg, sizeof(msg), "Opened %s", vmcorePath.c_str());
    res.AppendMessage(msg);
    return true;
  }
};

//--------------------------------------------------------------------------------------
// Plugin entry
//--------------------------------------------------------------------------------------

namespace lldb {

bool PluginInitialize(lldb::SBDebugger debugger) {
  auto interp = debugger.GetCommandInterpreter();
  debugger.SetPrompt("kLLDB> ");

  lldb::SBCommand cmdGroup = interp.AddMultiwordCommand(
      "kdump", "Commands for Linux vmcore/kdump analysis");
  if (!cmdGroup.IsValid()) {
    ::fprintf(stderr, "Failed to create 'linux kdump' cmd group.\n");
    return false;
  }

  cmdGroup.AddCommand("open", new CoreOpenCommand(),
                      "Open a kdump file: kdump open <crash file>");
  cmdGroup.AddCommand("bugpoint", new CoreBugpointCommand(),
                      "Show bugpoint based on rbp and rip");
  cmdGroup.AddCommand("info", new CoreInfoCommand(),
                      "Show top-level info from the dump");
  cmdGroup.AddCommand("registers", new CoreRegistersCommand(),
                      "Show registers content from dump file");
  cmdGroup.AddCommand("load-lkm", new CoreLoadLKMCommand(),
                      "Load a kernel module");
  cmdGroup.AddCommand("source-dir-map", new CoreSourceDirMapCommand(),
                      "Map remote source directories to local paths");

  ::printf("kLLDBOffline plugin loaded.\n");
  return true;
}

} // namespace lldb
