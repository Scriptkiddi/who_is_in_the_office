from scapy.all import DHCP, Ether
from scapy.all import sniff
from threading import Thread
from slacker import Slacker
import subprocess
from time import sleep, time, mktime
from datetime import datetime, timedelta

mac_to_name = {"<mac-id>": "<Name of the person belonging to this id>", }
token = "<your-slack-token>"
channel = "<channel-name-without-#>"
#pattern_matching = ["Frederik", "Fritz", "Larissa", "Jonas"]
slack = Slacker(token)
def watchdog_thread_if_device_leaves(slack, mac, name):
    counter = 0
    while True:
        sleep(5)
        p = subprocess.Popen("arp-scan -l | grep {}".format(mac), stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        if not output:
            counter += 1
        if output:
            counter = 0
        if counter==30:
            slack.chat.post_message('#{}'.format(channel), '{} left the Office!'.format(name))
            break
    

def listen_for_dhcp_packages(packet): 
    if DHCP in packet and packet[DHCP].options[0][1] == 3:
        if packet[Ether].src in mac_to_name.keys():
    
            mac_address = packet[Ether].src
            name = mac_to_name.get(packet[Ether].src)
            message = '{} is in the office now!'.format(name)
            channel_id = slack.channels.get_channel_id(channel)
            r = slack.channels.history(channel_id, time(), mktime((datetime.now()-timedelta(hours=1)).timetuple()))
            if r.body.get('messages')[0].get('text') != message:
                slack.chat.post_message('#{}'.format(channel), message)
                Thread(target=watchdog_thread_if_device_leaves, args=(slack, mac_address, name)).start()




            
sniff(filter="arp or (udp and (port 67 or 68))", prn=listen_for_dhcp_packages, store=0)
