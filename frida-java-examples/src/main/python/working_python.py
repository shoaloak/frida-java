import frida
import shutil

script_source = r"""
(function () {
    function sendInfo(obj) {
        send({ type: "info", data: obj })
    }

    const mainModule = Process.enumerateModules()[0]

    sendInfo({
        name: mainModule.name,
        path: mainModule.path,
        base: mainModule.base.toString(),
        size: mainModule.size
    })
})();
"""

def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if payload["type"] == "info":
            print("Binary info from agent:")
            for k, v in payload["data"].items():
                print(f"  {k}: {v}")
    else:
        print("Message:", message)

def main():
    device = frida.get_local_device()

    bash_path = shutil.which("bash")
    if not bash_path:
        raise RuntimeError("bash not found")

    pid = device.spawn([bash_path, "--help"],
                       stdio="pipe")

    print("Spawned PID:", pid)

    session = device.attach(pid)

    script = session.create_script(script_source)
    script.on("message", on_message)

    script.load()
    print("Script loaded")

    device.resume(pid)
    print("Resumed process")

if __name__ == "__main__":
    main()

