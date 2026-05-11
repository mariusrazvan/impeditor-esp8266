WiFi Lab Firmware (Impeditor)

This firmware is designed for network analysis and management frame injection in a private, legal cybersecurity lab using an ESP8266 D1 Mini.  

Capabilities:
  The firmware utilizes low-level SDK calls to interact with 802.11 frames.
  Due to hardware limitations of the ESP8266, data frame payloads are truncated to approximately 36-48 bytes.  
Supported Features:
1. Active Scanning: Identify all visible and invisible Access Points (APs).  Management Frame Capture: Sniffing of BEACON, PROBE_REQ/RESP, AUTH, ASSOC_REQ/RESP, DEAUTH, and DISASSOC frames.  
2. Data Header Analysis: Observe source/destination MAC addresses, RSSI, and channel information.  
3. Broadcast Injection: Perform broadcast deauthentication (DEAUTH).  
4. Targeted Injection: Perform client-specific deauthentication (CDEAUTH) in either direction (AP to Client or Client to AP).  

Hardware Limitations:
1. No EAPOL Parsing: Payloads are truncated before EAPOL key data can be reached.  
2. No PMKID Extraction: The hardware cannot deliver the necessary payload size for extraction.  
3. Limited Data Inspection: Payload-level analysis (DHCP, ARP, etc.) is not possible on this hardware.  

Setup Process:
  This firmware must be compiled with the Spacehuhn Deauther SDK. The standard ESP8266 Arduino core blocks the injection of management frames required for deauthentication.  
1. Add Board URL: In Arduino IDE, go to Preferences and add the following to "Additional Boards Manager URLs":
https://raw.githubusercontent.com/SpacehuhnTech/arduino/main/package_spacehuhn_index.json  
2. Install Board: Open Boards Manager, search for "deauther," and install "Deauther ESP8266 Boards".  
3. Select Board: Go to Tools > Board > Deauther ESP8266 Boards and select LOLIN(WEMOS) D1 R2 & mini.  

Configure Tools: 
  Set the following parameters in the Tools menu:  
1. CPU Frequency: 80MHz
2. Flash Size: 4MBUpload
3. Speed: 921600

Flash: Connect your D1 Mini and upload the code.
