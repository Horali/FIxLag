import json
import sys
import time
from pathlib import Path

import frida

HERE = Path(r"C:\Users\child\AppData\Local\Temp\mlbb-radar\frida\prototypes")


def main():
    pid = int(sys.argv[1])
    probe = sys.argv[2] if len(sys.argv) > 2 else "list_assemblies.js"
    seconds = float(sys.argv[3]) if len(sys.argv) > 3 else 30

    src = ("(() => {\nconst PROTOTYPE_OPTIONS = " + json.dumps(
        {"mode": "any", "phase": "any", "scanBytes": 1048576, "scanMs": 1000}) + ";\n"
        + (HERE / "runtime.js").read_text(encoding="utf-8") + "\n"
        + (HERE / probe).read_text(encoding="utf-8") + "\n})();\n")

    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27043")
    session = dev.attach(pid)
    script = session.create_script(src)
    done = {"v": False}

    def on_msg(message, data):
        if message.get("type") != "send":
            print("FRIDA", json.dumps(message)[:200])
            return
        p = message.get("payload", {})
        if p.get("event") == "summary":
            done["v"] = True
        print(json.dumps(p, ensure_ascii=False))

    script.on("message", on_msg)
    script.load()
    end = time.time() + seconds
    while time.time() < end and not done["v"]:
        time.sleep(0.3)
    try:
        script.unload()
    except Exception:
        pass
    session.detach()


if __name__ == "__main__":
    main()
