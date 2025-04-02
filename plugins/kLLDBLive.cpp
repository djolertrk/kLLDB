//
// kLLDBLive.cpp by djolertrk
//

#include <lldb/API/SBAddress.h>
#include <lldb/API/SBCommandInterpreter.h>
#include <lldb/API/SBCommandReturnObject.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/API/SBFrame.h>
#include <lldb/API/SBTarget.h>
#include <lldb/API/SBThread.h>
#include <lldb/API/SBValue.h>

#include <limits.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

// Convenient macro to ensure the symbol remains in the plugin.
#define API __attribute__((used))

using namespace lldb;

static std::string g_vmlinux_path = "vmlinux";

static std::vector<std::string> g_module_search_paths;

static bool FileExists(const std::string &path) {
  struct stat st;
  return (stat(path.c_str(), &st) == 0);
}

// Utility to make path absolute via realpath() if possible
static std::string MakeAbsolutePath(const std::string &path) {
  char resolved[PATH_MAX];
  if (realpath(path.c_str(), resolved)) {
    return std::string(resolved);
  }
  // If realpath fails (e.g. file doesn't exist yet), fallback:
  return path;
}

class LxSymbolsCommand : public SBCommandPluginInterface {
public:
  bool DoExecute(SBDebugger debugger, char **command,
                 SBCommandReturnObject &result) override {

    // 1) Collect all arguments as .ko file paths
    std::vector<std::string> ko_paths;
    while (command && command[0]) {
      std::string arg = command[0];
      command++;
      ko_paths.push_back(arg);
    }

    if (ko_paths.empty()) {
      result.AppendMessage("Usage: linux symbols /path/to/module.ko [...]\n");
      result.SetStatus(eReturnStatusFailed);
      return false;
    }

    // 2) Create or re-create the main kernel target from g_vmlinux_path
    SBTarget target = debugger.GetSelectedTarget();
    if (target.IsValid()) {
      // If already valid, remove it to get a clean slate
      debugger.DeleteTarget(target);
    }

    SBError error;
    target = debugger.CreateTarget(g_vmlinux_path.c_str(), nullptr, nullptr,
                                   false, error);
    if (!target.IsValid() || error.Fail()) {
      std::stringstream msg;
      msg << "Failed to create target from '" << g_vmlinux_path << "'\n"
          << "LLDB error: " << error.GetCString() << "\n";
      result.AppendMessage(msg.str().c_str());
      result.SetStatus(eReturnStatusFailed);
      return false;
    }

    // 3) For each .ko path, convert to absolute, then run "target modules add
    // <path>"
    //    This is the simplest approach to have LLDB parse the .ko as a module.
    for (auto &rel_path : ko_paths) {
      std::string abs_path = MakeAbsolutePath(rel_path);

      // Also check existence before passing to LLDB
      if (!FileExists(abs_path)) {
        std::stringstream msg;
        msg << "Skipping '" << rel_path << "': file not found.\n";
        result.AppendMessage(msg.str().c_str());
        continue;
      }

      std::string cmd = "target modules add \"" + abs_path + "\"";
      SBCommandReturnObject cmd_result;
      debugger.GetCommandInterpreter().HandleCommand(cmd.c_str(), cmd_result);

      if (cmd_result.GetStatus() != eReturnStatusSuccessFinishResult) {
        std::stringstream msg;
        msg << "Failed to add module '" << abs_path
            << "': " << cmd_result.GetError() << "\n";
        result.AppendMessage(msg.str().c_str());
      } else {
        std::stringstream msg;
        msg << "Added module: " << abs_path << "\n";
        result.AppendMessage(msg.str().c_str());
      }
    }

    // 4) Done
    result.AppendMessage("linux-symbols: All requested modules processed.\n");
    result.SetStatus(eReturnStatusSuccessFinishResult);
    return true;
  }
};

class LxConfigCommand : public SBCommandPluginInterface {
public:
  bool DoExecute(SBDebugger debugger, char **command,
                 SBCommandReturnObject &result) override {
    if (!command || !command[0]) {
      std::stringstream msg;
      msg << "Current vmlinux path: " << g_vmlinux_path << "\n";
      msg << "Usage: linux config /path/to/vmlinux\n";
      result.AppendMessage(msg.str().c_str());
      result.SetStatus(eReturnStatusFailed);
      return false;
    }

    g_vmlinux_path = command[0];

    std::stringstream msg;
    msg << "kLLDB: vmlinux path set to: " << g_vmlinux_path << "\n";
    result.AppendMessage(msg.str().c_str());
    result.SetStatus(eReturnStatusSuccessFinishResult);
    return true;
  }
};

class LxConnectCommand : public SBCommandPluginInterface {
public:
  bool DoExecute(SBDebugger debugger, char **command,
                 SBCommandReturnObject &result) override {
    // Figure out the port spec
    // If user typed "linux connect :1234", prepend "127.0.0.1"
    // Default is "127.0.0.1:1234"
    std::string host_port = "127.0.0.1:1234";
    if (command && command[0]) {
      host_port = command[0];
      if (!host_port.empty() && host_port.front() == ':') {
        host_port = "127.0.0.1" + host_port; // => "127.0.0.1:1234"
      }
    }

    // Create an LLDB target object directly via the API
    SBError error;
    SBTarget target = debugger.CreateTarget(g_vmlinux_path.c_str(), // file
                                            nullptr,                // triple
                                            nullptr,                // platform
                                            false, // add_dependent_modules
                                            error);
    if (error.Fail() || !target.IsValid()) {
      std::stringstream msg;
      msg << "Failed to create target with '" << g_vmlinux_path << "'\n"
          << "LLDB error: " << error.GetCString();
      result.AppendMessage(msg.str().c_str());
      result.SetStatus(eReturnStatusFailed);
      return false;
    }

    // Connect to QEMU’s GDB stub via the process connect command
    std::string connect_cmd = "gdb-remote " + host_port;

    SBCommandReturnObject connect_result;
    debugger.GetCommandInterpreter().HandleCommand(connect_cmd.c_str(),
                                                   connect_result);

    if (connect_result.GetStatus() != eReturnStatusSuccessFinishResult) {
      std::stringstream msg;
      msg << "Failed to connect to GDB stub at " << host_port << "\n"
          << connect_result.GetError();
      result.AppendMessage(msg.str().c_str());
      result.SetStatus(eReturnStatusFailed);
      return false;
    }

    // If all is well
    std::stringstream msg;
    msg << "kLLDB: Connected to GDB stub at " << host_port << "\n"
        << "Using vmlinux path: " << g_vmlinux_path << "\n";
    result.AppendMessage(msg.str().c_str());
    result.SetStatus(eReturnStatusSuccessFinishResult);
    return true;
  }
};

// Command: linux linux stop
class LxLinuxStopCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger debugger, char **command,
                 lldb::SBCommandReturnObject &result) override {
    lldb::SBCommandReturnObject interrupt_result;
    debugger.GetCommandInterpreter().HandleCommand("process interrupt",
                                                   interrupt_result);

    if (interrupt_result.GetStatus() ==
        lldb::eReturnStatusSuccessFinishResult) {
      result.AppendMessage("Process interrupted (like 'process interrupt').\n");
      result.SetStatus(lldb::eReturnStatusSuccessFinishResult);
    } else {
      result.AppendMessage("Failed to interrupt the process.\n");
      result.SetStatus(lldb::eReturnStatusFailed);
    }
    return true;
  }
};

// Command: linux linux status
class LxLinuxStatusCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger debugger, char **command,
                 lldb::SBCommandReturnObject &result) override {
    lldb::SBCommandReturnObject status_result;
    debugger.GetCommandInterpreter().HandleCommand("process status",
                                                   status_result);

    // Pass the status output to our caller
    result.AppendMessage(status_result.GetOutput());
    // The sub-command's status is success if the underlying command succeeded
    if (status_result.GetStatus() == lldb::eReturnStatusSuccessFinishResult) {
      result.SetStatus(lldb::eReturnStatusSuccessFinishResult);
    } else {
      result.SetStatus(lldb::eReturnStatusFailed);
    }
    return true;
  }
};

class LxLinuxContinueCommand : public lldb::SBCommandPluginInterface {
public:
  bool DoExecute(lldb::SBDebugger debugger, char **command,
                 lldb::SBCommandReturnObject &result) override {
    // 1) Make sure we have a valid target
    SBTarget target = debugger.GetSelectedTarget();
    if (!target.IsValid()) {
      result.AppendMessage("No valid target selected.\n");
      result.SetStatus(lldb::eReturnStatusFailed);
      return false;
    }

    // 2) Make sure we have a valid process
    SBProcess process = target.GetProcess();
    if (!process.IsValid()) {
      result.AppendMessage("No valid process. Must be connected.\n");
      result.SetStatus(lldb::eReturnStatusFailed);
      return false;
    }

    // 3) Force synchronous mode if you want GDB-like blocking
    //    Telling LLDB "run in sync mode"
    debugger.SetAsync(false);

    // 4) Actually continue via the SB API
    SBError err = process.Continue();
    if (err.Fail()) {
      // 'Continue()' can fail if the process is not in a "stopped" state or if
      // there's an internal LLDB error.
      std::stringstream msg;
      msg << "Failed to continue the process: " << err.GetCString();
      result.AppendMessage(msg.str().c_str());
      result.SetStatus(lldb::eReturnStatusFailed);
      return false;
    }

    // If we get here, LLDB is blocking until the target stops again (breakpoint
    // or manual interrupt).
    // Once the target is stopped, we resume control in the plugin code:
    result.AppendMessage("Process continued synchronously.\n");
    result.SetStatus(lldb::eReturnStatusSuccessFinishResult);
    return true;
  }
};

//
// Plugin initialization entry point for LLDB 10+
//
namespace lldb {
bool PluginInitialize(SBDebugger debugger) {
  SBCommandInterpreter interpreter = debugger.GetCommandInterpreter();
  debugger.SetPrompt("kLLDB> ");

  // Create a multiword command group named "linux" for Linux kernel helper
  // commands
  SBCommand linuxGroup =
      interpreter.AddMultiwordCommand("linux", "Linux kernel helper commands");
  if (linuxGroup.IsValid()) {
    linuxGroup.AddCommand("symbols", new LxSymbolsCommand(),
                          "Load Linux kernel and module symbols", nullptr);

    linuxGroup.AddCommand(
        "config", new LxConfigCommand(),
        "Set or show the path to vmlinux. Usage: linux config /path/to/vmlinux",
        nullptr);

    // Add subcommand: connect
    linuxGroup.AddCommand(
        "connect", new LxConnectCommand(),
        "Connect to a remote GDB server. Usage: linux connect :1234", nullptr);

    linuxGroup.AddCommand("stop", new LxLinuxStopCommand(),
                          "Interrupt linux kernel process.", nullptr);

    linuxGroup.AddCommand("status", new LxLinuxStatusCommand(),
                          "Show linux kernel process status).", nullptr);

    linuxGroup.AddCommand("continue", new LxLinuxContinueCommand(),
                          "Continue linux kernel process execution.", nullptr);
  }

  // Inform the user that the plugin loaded successfully
  printf("kLLDB plugin initialized successfully.\n");
  return true;
}
} // namespace lldb
