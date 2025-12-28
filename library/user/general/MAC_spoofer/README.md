# MAC Spoofer

**MAC Spoofer** is an identity management payload for the WiFi Pineapple Pager.

### Features

* **Smart Interface Sorting:** Automatically prioritizes client (`wlan0cli`) and monitor (`wlan1mon`) interfaces for faster selection.
* **True Hardware Detection:** Identifies the permanent factory MAC address for backups, ensuring "Restore" always reverts to the real hardware state.
* **Categorized Identities:** Profiles are grouped by environment (Home, Corporate, Commercial, Industrial, Wired) for quick selection.
* **Safety Restore:** Includes a "Restore Original" option to revert to factory settings without rebooting.

### Workflow Tutorial

**1. Workflow Briefing** The payload begins with a brief overview of the process and a safety warning regarding network disconnection.
![Startup](screens/Capture01.PNG)

**2. Select Interface** The tool scans for all available network interfaces, prioritizing the most useful ones at the top of the list. Enter the ID of the interface you wish to spoof.
![Interface List](screens/Capture02.PNG)

![Interface Selection](screens/Capture03.PNG)

**3. Select Environment** Choose the category that matches your target environment. (0: Restore, 1-5: Spoof Profiles).
![Environment List](screens/Capture04.PNG)

![Category Selection](screens/Capture05.PNG)

**4. Select Device Profile** Select the specific device to emulate. The script generates a valid MAC address using that vendor's OUI and a randomized suffix.
![Profile List](screens/Capture06.PNG)

![Profile Selection](screens/Capture07.PNG)

**5. Confirm Action** Review your selection. The screen displays the target Interface, the new Hostname, and the new MAC address for confirmation.
![Confirm Spoof](screens/Capture08.PNG)

**6. Apply & Verify** The tool temporarily disables the network interface, applies the new identity, and re-enables it. It then verifies the active state against the kernel.
![Success](screens/Capture09.PNG)

### Technical Notes

* **Persistence:** All changes are volatile. Rebooting the device will automatically reset the MAC address to its hardware default.
* **Connection Drop:** Running this payload while connected to a network will drop the connection. Reconnection is required after the spoof is applied.

