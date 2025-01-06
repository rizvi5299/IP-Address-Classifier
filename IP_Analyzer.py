import pandas as pd
import json

def main():

    with open('ipaddresses.json', 'r') as file: # load the json file here
        data = json.load(file)
        ips = data['IPs']

    df = pd.DataFrame(ips, columns=['IP Address'])

    # applying the functions to create the columns for each IP address
    df['Class'] = df['IP Address'].apply(ipclass)
    df['Valid (Y/N)'] = df['IP Address'].apply(isvalid)
    df['RFC 1918 (Y/N)'] = df['IP Address'].apply(rfc1918)
    df['Default Mask (Subnet Mask)'] = df['IP Address'].apply(subnetmask)
    df['Numeric Representation (Decimal)'] = df['IP Address'].apply(todecimal)

    # defining the multi-level column header
    header = pd.MultiIndex.from_tuples([
        ('IP Address', '', ''),
        ('      Class', '',''),
        ('  Valid', '(Y/N)',''),
        ('  RFC 1918', '(Y/N)',''),
        ('      Default Mask', '(Subnet Mask)',''),
        ('  Numeric Representation', '(Decimal)','')
    ])

    # update the df to use the multi-level column header
    df.columns = header

    # adjusting display options
    pd.set_option('display.max_columns', None)
    pd.set_option('display.expand_frame_repr', False)

    print(df.to_string(index=False))


def ipclass(ip): # get the class of the address
    try:
        parts = ip.split('.')
        first_octet = int(parts[0])
        if 1 <= first_octet <= 126:
            return 'A'
        elif 128 <= first_octet <= 191:
            return 'B'
        elif 192 <= first_octet <= 223:
            return 'C'
        elif 224 <= first_octet <= 239:
            return 'D'
        elif 240 <= first_octet <= 255:
            return 'E'
        elif first_octet>255:
            return 'N/A'
        else:   #for 0, 127
            return 'Special'
    except (ValueError, IndexError):
        return 'N/A'

def rfc1918(ip): #checks for rfc 1918
    try:
        first, second, third, fourth = map(int, ip.split('.'))
    except ValueError:
        return 'N'

    if first not in [10, 172, 192]: #only these 3 first octets can be RFC 1918
        return 'N'

    if first == 10:   #check the other 3 octets to see if in range
        if not (second >= 0 and second <= 255 and third >= 0 and third <= 255 and fourth >= 0 and fourth <= 255):
            return 'N'
    elif first == 172:
        if not (second >= 16 and second <= 31 and third >= 0 and third <= 255 and fourth >= 0 and fourth <= 255):
            return 'N'
    elif first == 192:
        if not (second == 168 and third >= 0 and third <= 255 and fourth >= 0 and fourth <= 255):
            return 'N'

    return 'Y'


def isvalid(ip):  #checks if it has four octets, each within 0-255.
    try:
        octets = list(map(int, ip.split('.')))
    except ValueError:
        return 'N'

    if len(octets) != 4:
        return 'N'

    for octet in octets:
        if octet < 0 or octet > 255:
            return 'N'

    return 'Y'


def subnetmask(ip): # simply returns subnet mask only if class A,B, or C.
    IPclass = ipclass(ip) #first find class of IP using ipclass fucntion.
    if IPclass not in ['A','B','C'] or isvalid(ip) == 'N': return 'Not Applicable' #only these three classes have default subnet masks.
    if IPclass == 'A': return '255.0.0.0'
    if IPclass == 'B': return '255.255.0.0'
    else: return '255.255.255.0' #meaning, its class C.

def todecimal(ip):  #calculates decimal value of a ip address by bitwise left shifting
    if isvalid(ip) == 'N': return 'Not Applicable'  #Not Applicable for invalid IPs
    octets = ip.split('.')
    if len(octets) != 4:
        return 'Not Applicable'
    try:
        decimal_ip = (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])
        return decimal_ip
    except ValueError:
        return 'Not Applicable'

if __name__ == "__main__":
    main()
