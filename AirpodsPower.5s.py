#!/usr/bin/env python3

# <bitbar.title>AirPods Power</bitbar.title>
# <bitbar.version>v1.1</bitbar.version>
# <bitbar.author>Jonathan Kula</bitbar.author>
# <bitbar.author.github>jdkula</bitbar.author.github>
# <bitbar.desc>Displays AirPods battery</bitbar.desc>
# <bitbar.dependencies>python3,blueutil</bitbar.dependencies>

# Based on AirPods Battery CLI, Version 2.3 - https://github.com/duk242/AirPodsBatteryCLI
# and gonzaloserrano's original BitBar plugin, https://getbitbar.com/plugins/System/AirPodsPower.sh
# Icon by icons8 - https://visualpharm.com/free-icons/airpods-595b40b85ba036ed117dbec2

from subprocess import run
from re import search

PROPERTY_POSSIBILITIES = [
    "BatteryPercentCombined",
    "HeadsetBattery",
    "BatteryPercentSingle",
    "BatteryPercentLeft",
    "BatteryPercentRight",
    "BatteryPercentCase"
]

AIRPODS_IMAGE = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAFZ2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNS41LjAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICAgeG1sbnM6ZXhpZj0iaHR0cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIgogICAgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIKICAgZXhpZjpQaXhlbFhEaW1lbnNpb249IjE2IgogICBleGlmOlBpeGVsWURpbWVuc2lvbj0iMTYiCiAgIGV4aWY6Q29sb3JTcGFjZT0iMSIKICAgdGlmZjpJbWFnZVdpZHRoPSIxNiIKICAgdGlmZjpJbWFnZUxlbmd0aD0iMTYiCiAgIHRpZmY6UmVzb2x1dGlvblVuaXQ9IjIiCiAgIHRpZmY6WFJlc29sdXRpb249IjcyLjAiCiAgIHRpZmY6WVJlc29sdXRpb249IjcyLjAiCiAgIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiCiAgIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIKICAgeG1wOk1vZGlmeURhdGU9IjIwMjAtMDYtMjZUMDI6MDYtMDc6MDAiCiAgIHhtcDpNZXRhZGF0YURhdGU9IjIwMjAtMDYtMjZUMDI6MDYtMDc6MDAiPgogICA8ZGM6dGl0bGU+CiAgICA8cmRmOkFsdD4KICAgICA8cmRmOmxpIHhtbDpsYW5nPSJ4LWRlZmF1bHQiPkFpcnBvZHMtNTk1YjQwYjg1YmEwMzZlZDExN2RiZWMyPC9yZGY6bGk+CiAgICA8L3JkZjpBbHQ+CiAgIDwvZGM6dGl0bGU+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InByb2R1Y2VkIgogICAgICBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZmZpbml0eSBEZXNpZ25lciAoTWFyIDMxIDIwMjApIgogICAgICBzdEV2dDp3aGVuPSIyMDIwLTA2LTI2VDAyOjA2LTA3OjAwIi8+CiAgICA8L3JkZjpTZXE+CiAgIDwveG1wTU06SGlzdG9yeT4KICA8L3JkZjpEZXNjcmlwdGlvbj4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+Cjw/eHBhY2tldCBlbmQ9InIiPz4J2sgjAAABgmlDQ1BzUkdCIElFQzYxOTY2LTIuMQAAKJF1kc8rRFEUxz/zg/FjRLGQLCYNK8SoiY0yEmrSNEYZbGae+aHmx+u9kWSrbKcosfFrwV/AVlkrRaRkZWFNbJie82amRjLndu753O+953TvuWANpZS0bh+AdCanBSd9rvnwgsvxQi0d1GPHG1F0dSwQ8FPVPu+xmPG2z6xV/dy/1rgc0xWw1AmPKqqWE54S9q/lVJN3hNuUZGRZ+Ey4V5MLCt+ZerTEryYnSvxtshYKjoO1RdiV+MXRX6wktbSwvBx3OrWqlO9jvsQZy8zNSuwS70QnyCQ+XEwzwTheBhmR2UsfHvplRZX8gWL+DFnJVWRWWUdjhQRJcvSKuirVYxLjosdkpFg3+/+3r3p8yFOq7vRBzbNhvHeDYxsKecP4OjKMwjHYnuAyU8nPHsLwh+j5iuY+gOZNOL+qaNFduNiC9kc1okWKkk3cGo/D2yk0haH1BhoWSz0r73PyAKEN+apr2NuHHjnfvPQDTRtn2mD6i3EAAAAJcEhZcwAACxMAAAsTAQCanBgAAAEXSURBVDiN7Y+9ToRAEMfHZfkKkMvxURl4DBrehYTQUVvYERofws5HcTsbqLbaWBg97zRaXeEW647NcTnOI7EwsfFXzm/mPzMAv8TCMIxrSulrEASPnud1R/4sjuOr5XK5tizrzff9GwBY7K1t27dlWW455yiEwDzP3ymlF6P3ff+yKIqtEAI551hV1YfruuxwA2qtcaTve4yi6GGUSZI8DcOw91prBACcBCAitm2LiIhKKSSE6FESQrRSatIzCTAM47lpmg1jDKWU3xt2C6SUyBjDuq7vCSGrwwvOAaALw3DIskzPBaRp+ul53h0AdLuZk8xecPw3AACZS/kp/wEnsG17DQDouu7LWHMcZwMAaJrman7yr/gCMqWjHII+9WcAAAAASUVORK5CYII='

HEADER_PARAMS = " | size=12 image=" + AIRPODS_IMAGE
CONNECTED_PARAMS = " | color=darkgreen"


def is_headphone(line):
    return "Minor Type: Headphones" in line or "Minor Type: Headset" in line


def get_device_metadata():
    devices = []

    sys_profile_lines = run(
        ["system_profiler", "SPBluetoothDataType"],
        capture_output=True,
        text=True).stdout.split("\n")

    for i in range(len(sys_profile_lines)):
        if is_headphone(sys_profile_lines[i]):
            name = sys_profile_lines[i - 3].replace(":", "").strip()
            mac = sys_profile_lines[i - 2].replace("Address:", "").strip()
            connected = "Yes" in sys_profile_lines[i + 4]

            devices.append({
                "mac": mac.lower(),
                "name": name,
                "connected": connected
            })

    return devices


def get_properties(info):
    properties = {}

    for property in PROPERTY_POSSIBILITIES:
        match = search(property + " = (\\d*)", info)
        if match and match.group(1):
            properties[property] = int(match.group(1))

    return properties


def get_device_info(metadata):
    devices = []

    bt_defaults_lines = run(
        ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth"],
        capture_output=True,
        text=True).stdout.split("\n")

    for device in metadata:
        mac = device["mac"]
        device_info = device

        for i in range(len(bt_defaults_lines)):
            if mac in bt_defaults_lines[i]:
                info = "\n".join(bt_defaults_lines[i:i + 6])

                properties = get_properties(info)

                for key in properties.keys():
                    device_info[key] = properties[key]

        devices.append(device_info)

    return devices


def get_last_upper_index(s):
    for i in range(len(s) - 1, -1, -1):
        if s[i].isupper():
            return i
    return None


def get_device_header(device):
    if device is None or not device["connected"]:
        return "✗" + HEADER_PARAMS

    output = ""
    for key in PROPERTY_POSSIBILITIES:
        if key not in device:
            continue

        if device[key] > 0:
            tag = key[get_last_upper_index(key) or 0]
            output += tag + str(device[key]) + ' '

    if not output:
        output += "✔"

    return output + HEADER_PARAMS


def get_device_detail(device):
    output = ""
    output += device["name"]

    if device["connected"]:
        output += CONNECTED_PARAMS
        output += "\n"
        for key in PROPERTY_POSSIBILITIES:
            if key not in device:
                continue
            last = get_last_upper_index(key) or 0
            if device[key] > 0:
                output += key[last:] + ": " + str(device[key]) + "%\n"
        output += "Disconnect | refresh=true terminal=false bash=/usr/local/bin/blueutil param1=--disconnect param2="
    else:
        output += "\n"
        output += "Connect | refresh=true terminal=false bash=/usr/local/bin/blueutil param1=--connect param2="
    output += device["mac"]
    output += "\n"
    output += "---"
    return output


def main():
    device_info = sorted(get_device_info(get_device_metadata()), key=lambda device: not device["connected"])

    first_device = device_info[0] if len(device_info) > 0 else None

    print(get_device_header(first_device))

    print("---")
    print("Refresh | refresh=true")
    print("---")

    for device in device_info:
        print(get_device_detail(device))

    print("---")
    print("Bluetooth Preferences | terminal=false bash=/usr/bin/open "
          "param1=/System/Library/PreferencePanes/Bluetooth.prefPane")
    print("Sound Preferences | terminal=false bash=/usr/bin/open "
          "param1=/System/Library/PreferencePanes/Sound.prefPane")


if __name__ == "__main__":
    main()
