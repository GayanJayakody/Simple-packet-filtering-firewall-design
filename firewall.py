import csv
rulesFile = "firewall_rules.csv"
inputInterfaceFile = 'interface_1.txt'
outputInterfaceFile = 'interface_2.txt'

def writeToDictionary(packet):
    # write necessary details in ip datagram into data structure
    pktDetails = {}
    pktDetails["protocol"] = packet[69:71]     #TCP = 06  UDP = 11
    pktDetails["source address"] = packet[78:89]
    pktDetails["destination address"] = packet[90:101]
    pktDetails["source port"] = packet[102:107]
    pktDetails["destination port"] = packet[108:113]
    if (pktDetails["protocol"] == "06"):
        pktDetails["flag"] = packet[141:143]    # ACK set = 10 SYN = 02
    return pktDetails

def rejectPacket():
    print('Packet rejected by the firewall')

def passPacket(outputInterface,datagram):
    with open(outputInterface, "a+") as outputFile:
        outputFile.seek(0)
        data = outputFile.read(10)
        if len(data) > 0 :
            outputFile.write("\n")
        outputFile.write(datagram)
    print('packet accepted by the firewall')


                
def firewall(packet):
    
    ipDatagram = writeToDictionary(packet)
    with open(rulesFile, mode ='r') as file:
             
        csvFile = csv.DictReader(file)         # read firewall filtering rules
        flag = False
        for row in csvFile: 
           
            if (flag==True):
                break
            if (ipDatagram["protocol"] == '11'):  # UDP filtering
                if((ipDatagram["source address"] == row['Source address'] or row['Source address'] == 'Any') and 
                (ipDatagram["destination address"] == row["Destination address"] or row["Destination address"] == 'Any')  and 
                (ipDatagram["source port"] == row["Source port"] or row["Source port"] == 'Any')  and 
                (ipDatagram["destination port"] == row["Destination port"] or row["Destination port"] == 'Any')):
                    flag = True
                    if(row['Action'] == 'Deny'):
                        rejectPacket()
                        continue
                    elif(row['Action'] == 'Allow'):
                        passPacket(outputInterfaceFile,packet)
                        continue

            elif (ipDatagram["protocol"] == '06'):  # TCP filtering
                if((ipDatagram["source address"] == row['Source address'] or row['Source address'] == 'Any') and 
                (ipDatagram["destination address"] == row["Destination address"] or row["Destination address"] == 'Any')  and 
                (ipDatagram["source port"] == row["Source port"] or row["Source port"] == 'Any')  and 
                (ipDatagram["destination port"] == row["Destination port"] or row["Destination port"] == 'Any')  and
                (ipDatagram["flag"] == row["ACK"] or row["ACK"] == 'Any')):
                    flag = True
                    if(row['Action'] == 'Deny'):
                        rejectPacket()
                        continue
                    elif(row['Action'] == 'Allow'):
                        passPacket(outputInterfaceFile,packet)
                        continue
        if (flag == False):
            passPacket(outputInterfaceFile,packet)

count = 0  
with open(inputInterfaceFile) as inputFile: 
    for datagram in inputFile: 
        count += 1
        firewall(datagram)
