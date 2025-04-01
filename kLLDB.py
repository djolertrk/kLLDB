# kLLDB by djolertrk

import lldb
import os

def __lldb_init_module(debugger, internal_dict):
    # Set the custom prompt for kLLDB
    debugger.HandleCommand("settings set prompt 'kLLDB> '")

    # Get the directory of this script (should be in bin/)
    script_dir = os.path.dirname(__file__)

    # Construct the path to the plugin in ../lib/
    plugin_path = os.path.join(script_dir, "..", "lib", "libkLLDBLive.so")
    plugin_path = os.path.abspath(plugin_path)

    # Load the plugin
    load_command = f"plugin load {plugin_path}"
    debugger.HandleCommand(load_command)

    print(f"kLLDB: Plugin loaded from {plugin_path}")
    print("kLLDB: Ready")
