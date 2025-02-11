from scapy.all import *
from SetUp import *
from prettytable import PrettyTable
import threading

AP_list = []
STA_list = []
networks = PrettyTable()
clients = PrettyTable()
interface = ""
channel = 0
channel_freq = ""
channel_flags  = ""


networks.field_names = ["No.", "BSSID", "SSID", "dBm_Signal", "Channel"]
clients.field_names = ["No.", "BSSID", "STA"]

def get_ch():
    return channel


def set_iface(ifc):
    global interface
    interface = ifc

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3
        ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "Hidden SSID"
        stats = packet[Dot11Beacon].network_stats()
        dBm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"
        channel = stats.get("channel")
        if not any(ap[0] == bssid for ap in AP_list):
            AP_list.append((bssid, channel))
            networks.add_row([len(AP_list), bssid, ssid, dBm_signal, channel])

            os.system("clear")
            print(networks)


def devices_discover(pkg, bssid):
    if pkg[Dot11].type == 2:

        if pkg.addr2 == bssid and pkg[Dot11].addr3 not in STA_list:
            STA_list.append(pkg[Dot11].addr3)
            clients.add_row([len(STA_list),bssid, pkg[Dot11].addr3])
            os.system("clear")  
            print(clients)
        
        elif pkg.addr3 == bssid and pkg.addr2 not in STA_list:
            STA_list.append(pkg[Dot11].addr2)
            clients.add_row([len(STA_list), bssid, pkg[Dot11].addr2])
            os.system("clear")  
            print(clients)
            


def AP_sniffing():
    try:
        channel_changer = Thread(target=change_channel, args= (interface,),daemon=True)
        channel_changer.start()
        sniff(prn = callback,iface = interface)
    except KeyboardInterrupt:
        print("\nExiting...\n")
    finally:
        stop_change_channel.set()
        if len(AP_list) == 0:
            print("\nNo AP found. Exiting...")
            return
        print("\nAP sniff exit...")



def STA_sniffing(index):
    try:   
        global channel 
        index = int(index)
        if index < 1 or index > len(AP_list):
            print(f"Enter index between 1 and {len(AP_list)}.")
            return
        
        
        channel = AP_list[index - 1][1]
        os.system(f"iw dev {interface} set channel {channel}")
        
        print(f"Sniffing AP {AP_list[index - 1][0]} at Channel {channel}...")
        sniff(prn=lambda pkt: devices_discover(pkt, AP_list[index - 1][0]), iface=interface)

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        print("\nClient sniff exit...")
