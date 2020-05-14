import netifaces
import argparse
import scapy.all as scapy
from scapy.layers.inet import TCP, IP
import signal
import sys

#This stores information on the packet source and destination, its ID, and its payload to check for duplicates
packet_dictionary = {}

#Takes arguments from the command and allocates them to interface, dump file, and expression
parser = argparse.ArgumentParser(description='Quantum Detector for Man on the Side attacks')
parser.add_argument('-i', '--interface')
parser.add_argument('-r', '--file')
parser.add_argument('expression')
args, leftover = parser.parse_known_args()

#Filters TCP packets only
def detect_layer(packet):
    return packet.haslayer(TCP)

#Handles the user pressing ^C since the program loops forever
def signal_handler(sig, frame):
    print('\nYou want to exit!\nStopping Sniffing...')
    sys.exit(0)

#Compares packets to check for a man on the side attack
def check_for_mots(packet):
    
    if(packet[IP].id != 0):
        #Creates a unique packet tuple of source IP address, destination IP address, source port number, destination port number
        packet_tuple = str(packet[IP].src) + " " + str(packet[IP].dst) + " "+ str(packet[TCP].sport) + " " + str(packet[TCP].dport)
    
        #If this packet tuple has an entry in the dictionary
        if packet_dictionary.get(packet_tuple) != None:
            #If the entry has a different ID from the incoming packet (not a retransmission)
            if packet_dictionary.get(packet_tuple)[0] != str(packet[IP].id):
                    #If the entry has the same payload as the incoming packet
                    if packet_dictionary.get(packet_tuple)[1] == str(packet[TCP].payload) and str(packet[TCP].payload) != '':
                        print 'An MOTS attack has been detected!'
                        print 'Happened at: ' + packet_tuple
                        print 'Happened between: ' + str(packet[IP].id) + ' and ' + str(packet_dictionary.get(packet_tuple))
        else:
                #If the packet tuple doesn't have an entry in the dictionary, add one for it with the ID and payload
                packet_dictionary[packet_tuple] = [str(packet[IP].id), str(packet[TCP].payload)]
                
        #When the dictionary reaches 100 entries, clear it out for memory efficiency        
        if len(packet_dictionary) == 100:
            packet_dictionary.clear

def main():
    #Handles keyboard interrupts
    signal.signal(signal.SIGINT, signal_handler)

    #Sets the default interface if no interface is provided
    if args.interface is None:
        print 'No interface provided, using default!\n'
        args.interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

    #Sniffs TCP packets with the expression provided offline from a given tcpdump file
    if args.file is not None:
        print 'File provided, detecting attack offline!\n'

        packet = scapy.sniff(offline=args.file, prn=check_for_mots,
              lfilter=detect_layer)
        print packet

    #Sniffs TCP packets with the expression provided online on the network
    else:
        print 'File not provided, detecting attack on network!\n'
        while(True):
            scapy.sniff(iface=args.interface, filter=args.expression, prn=check_for_mots,
              lfilter=detect_layer)


if __name__ == "__main__":
    main()
