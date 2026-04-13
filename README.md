# Fog Security
This project aims to secure the transit of sensitive medical records in a health monitoring system. The architecture consists of wearable devices (sensors), fog layer, and cloud.
Our main focus is to secure the sensors -> fog architecure. 

The proposed architecture is as follows:
1. Use **Ascon-128** for encryption
2. Use **CoAP / MQTT-SN** for low-power devices
3. Use **CBOR** for payload compression
4. Deploy **IDS at fog layer**
5. Use **explainable AI models**

Reference these notion notes for a better idea: [Notion](https://adaptable-boot-602.notion.site/Fog-Security-Lightweight-3295c38e056880e6865ccd3ba3d47e03?pvs=73)
## Core Idea
Efficient IoMT security =

**Fog computing + lightweight protocols + Ascon encryption + optimized payload + explainable IDS**

# Installation
1. clone the repo
2. open ```fog_security.ipynb```
3. open the Mosquitto broker
   ```
   cd mos2
   mosquitto.exe -v
   ```
   This broker was kindly packaged by [Steve's Internet Guide](http://www.steves-internet-guide.com/install-mosquitto-broker/). This prepacked mosquitto broker is far easier to set up and run rather than the manual windows installation.
   The broker should initalize on localhost:1883. opening this through the browser will not work as http is incompatible with mqtt
4. In ```fog_security.ipynb```, run the %pip install script and run all cells.
5. If you mqtt broker was successful, you will notice logs such as:
   <img width="1288" height="970" alt="image" src="https://github.com/user-attachments/assets/3f196d80-253b-4f8c-93a6-e9c621c7571a" />



## Referenced code
[Ascon](https://github.com/MinArchie/Fog-Security/tree/main)

[CBOR](https://github.com/brianolson/cbor_py)

[MQTT-Simulation](https://github.com/DamascenoRafael/mqtt-simulator)
