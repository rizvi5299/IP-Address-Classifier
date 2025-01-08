import pandas as pd
import json

EFFECTS = {
        "Green": "\033[32m",
        "Blue": "\033[34m",
        "RESET": "\033[0m",
        "Bold": "\033[1m",
    }

def main():  #this function creates the DF, applying all functions to the IP's

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
    
    finaldf = df.to_string(index=False)

    print(EFFECTS['Bold'] + EFFECTS['Green'] + '\nIP\'s Analyzed:\n\n' + EFFECTS['RESET'] + finaldf)
    menu(df)
    
        
def menu(df):
    while True:
        print(EFFECTS['Bold'] + EFFECTS['Blue'] + "\nMenu: Sort the Addresses" + EFFECTS['RESET'])
        print("1. Sort by Class")
        print("2. Sort by Valid (Y/N)")
        print("3. Sort by RFC 1918 (Y/N)")
        print("4. Sort by Default Mask (Subnet Mask)")
        print("5. Sort by Numeric Representation (Decimal)")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ")
        
        if choice == '1':
            df_sorted = df.sort_values(('      Class', '', ''), ascending=True)
            print(EFFECTS['Bold'] + EFFECTS['Green'] + "\nAddresses sorted by Class:\n" + EFFECTS['RESET'])
            print(df_sorted.to_string(index=False))
        elif choice == '2':
            df_sorted = df.sort_values(('  Valid', '(Y/N)', ''), ascending=True)
            print(EFFECTS['Bold'] + EFFECTS['Green'] + "\nAddresses sorted by Validity:\n"  + EFFECTS['RESET'])
            print(df_sorted.to_string(index=False))
        elif choice == '3':
            df_sorted = df.sort_values(('  RFC 1918', '(Y/N)', ''), ascending=True)
            print(EFFECTS['Bold'] + EFFECTS['Green'] + "\nAddresses sorted by RFC 1918:\n"  + EFFECTS['RESET'])
            print(df_sorted.to_string(index=False))
        elif choice == '4':
            df_sorted = df.sort_values(('      Default Mask', '(Subnet Mask)', ''), ascending=True)
            print(EFFECTS['Bold'] + EFFECTS['Green'] + "\nAddresses sorted by Default Mask (Subnet Mask):\n"  + EFFECTS['RESET'])
            print(df_sorted.to_string(index=False))
        elif choice == '5':
            df_sorted = df.iloc[df['  Numeric Representation', '(Decimal)'].apply(custom_sort).argsort()].reset_index(drop=True)
            print(EFFECTS['Bold'] + EFFECTS['Green'] + "\nAddresses sorted by Numeric Decimal Representation:\n"  + EFFECTS['RESET'])
            print(df_sorted.to_string(index=False))
        elif choice == '6':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 6.")

 
    
def custom_sort(value): #this is for sorting the numeric representation column
    if isinstance(value, str):
        return (0, value)  # Strings come first
    else:
        return (1, value)  # Integers come second
    

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
