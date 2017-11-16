import argparse
import atexit
import json
import os
import sys

import frida

from lib import scdecoder


def parse_message(message, data):
    msg_id = message["payload"]["id"]
    content = message["payload"]["content"]
    decoded = scdecoder.decode(msg_id, content, True)
    print(json.dumps(decoded, indent=4, sort_keys=False))


def instrument_debugger_checks():
    return open("dumper.js", "r").read()


def run_cmd(cmd):
    os.system(cmd)


def exit_handler():
    run_cmd("adb shell am force-stop " + package_name)


msg_seq = 0
package_name = "com.supercell.clashroyale"
path = ""

parser = argparse.ArgumentParser(description='CR Video Bot Controller.')

args = parser.parse_args()
atexit.register(exit_handler)

print("Killing " + package_name)
run_cmd("adb shell am force-stop " + package_name)
print("Starting " + package_name)
run_cmd("adb shell am start -n " + package_name + "/" + package_name + ".GameApp")

process = frida.get_usb_device().attach(package_name)
print("Frida attached.")
script = process.create_script(instrument_debugger_checks())
print("Dumper loaded.")
script.on('message', parse_message)
print("parse_message registered within script object.")
script.load()
sys.stdin.read()
