import os
import time
import subprocess
import threading
stop_change_channel = threading.Event()
def monitor_mode(iface):
    os.system('systemctl stop NetworkManager.service')
    os.system(f'ifconfig {iface} down')
    os.system(f'iwconfig {iface} mode monitor')
    os.system(f'ifconfig {iface} up')
    time.sleep(1)

def managed_mode(iface):
    os.system(f'ifconfig {iface} down')
    os.system(f'iwconfig {iface} mode managed')
    os.system(f'ifconfig {iface} up')
    os.system('systemctl start NetworkManager.service')
    time.sleep(1)

def change_channel(interface):
    channels_2ghz = list(range(1, 15))
    channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    all_channels = channels_2ghz + channels_5ghz

    ch_index = 0
    while not stop_change_channel.is_set():
        current_channel = all_channels[ch_index]
        os.system(f"iwconfig {interface} channel {current_channel}")
        print(f"Changed to channel: {current_channel}")
        ch_index = (ch_index + 1) % len(all_channels)
        time.sleep(2)
