# pyscrlink

Pyscrlink is [Scratch-link](https://github.com/LLK/scratch-link) for Linux.
Scratch-link is a software module which connects
[Scratch](https://scratch.mit.edu/) and Bluetooth devices such as
[micro:bit](https://microbit.org/). However, as of October 2020, it works only
on Windows and MacOS, and cannot connect Scratch and micro:bit on Linux
operating systems.

Pyscrlink allows Linux OSes to connect Scratch and bluetooth devices. It uses
Linux Bluetooth protocol stack [Bluez](http://www.bluez.org/) and its python
interfaces [pybluez](https://github.com/pybluez/pybluez) to handle Bluetooth,
and [bluepy](https://github.com/IanHarvey/bluepy) to handle Bluetooth Low
Energy, or BLE, connections. It is confirmed that pyscrlink connects Scratch
3.0 and a micro:bit, Lego Mindstorms EV3, Lego WeDo and Lego Boost.

Pyscrlink requires python version 3.6 and later to use websockets. If your
system has python older than version 3.6, install newer version. If your Linux
system has explicit command names python3 and pip3 for python version 3,
use them in the instructions below.

Confirmed Environments
----------------------
The instructions below was confirmed with following devices and distros.
Trial with other distros and feed-backs will be appreciated.

The pyscrlink (former bluepy-scratch-link) was confirmed with following devices,
Linux distros and browsers.

Devices:
* micro:bit by @kawasaki
* Lego Mindstorm EV3: by @chrisglencross

Linux distros:
* Arch Linux by @kawasaki
* elementary OS 5.0 Juno by @kawasaki
* Raspbian by @chirsglencross

Browsers:
* FireFox by @kawasaki
* Chromium by @kawasaki

Installation
------------
1. Prepare Bluetooth/BLE controller.

   Confirm that your Linux PC has a Bluetooth controller with BLE support.
   Bluetooth 4.0 controller supports BLE. If your PC does not have it, need
   to plug USB Bluetooth 4.0 adapter.

   Note: BLED112 USB dongle with Bluegiga BGAPI is not supported.

2. Install required packages.

    ```sh
    Ubuntu
    $ sudo apt install bluez libbluetooth-dev libnss3-tools libcap2-bin
    Arch
    $ sudo pacman -S bluez bluez-utils nss libcap
    ```

3. Install python modules.

    ```sh
    $ pip install pyscrlink
    Or if your system has python3 command,
    $ pip3 install pyscrlink
    ```

4. For Bluetooth Low Energy (BLE) devices, set bluepy-helper capability.

    ```
    $ bluepy_helper_cap
    Set capacbility 'cap_net_raw,cap_net_admin' to /usr/lib/python3.8/site-packages/bluepy-1.3.0-py3.8.egg/bluepy/bluepy-helper
    ```

    The command above requires super user privilege. It may request to input
    super user password.

5. For micro:bit, install Scratch-link hex on your device.

    * Download and unzip the [micro:bit Scratch Hex file](https://downloads.scratch.mit.edu/microbit/scratch-microbit-1.1.0.hex.zip).
    * Flash the micro:bit over USB with the Scratch .Hex File, you will see the
      five character name of the micro:bit scroll across the screen such as
      'zo9ev'.

Usage
-----
1. For Lego Mindstorms EV3, pair your Linux PC to the EV3 brick.

   First, turn on the EV3 and ensure Bluetooth is enabled.

   Then, pair using your Linux desktop's the Bluetooth settings.

   If using Gnome:
      * Settings -> Bluetooth
      * Click on the EV3 device name
      * Accept the connection on EV3 brick
      * Enter a matching PIN on EV3 brick and Linux PC. '1234' is the value Scratch suggests.
      * Confirm EV3 status is "Disconnected" in Bluetooth settings

   With a Raspberry Pi default Raspbian desktop, click the Bluetooth logo in the top right of the screen and
   Add Device. Then follow the Gnome instructions. You will be warned that the Raspberry Pi
   does not know how to talk to this device; that is not a problem.

   Alternatively you can perform pairing from the command-line:
   ```shell script
   $ bluetoothctl

   [bluetooth]# power on
   Changing power on succeeded

   [bluetooth]# pairable on
   Changing pairable on succeeded

   [bluetooth]# agent KeyboardOnly
   Agent registered

   [bluetooth]# devices
   ...
   Device 00:16:53:53:D3:19 EV3
   ...

   [bluetooth]# pair 00:16:53:53:D3:19
   Attempting to pair with 00:16:53:53:D3:19

   # Confirm pairing on the EV3 display, set PIN to 1234

   Request PIN code
   [agent] Enter PIN code: 1234
   [CHG] Device 00:16:53:53:D3:19 Connected: yes
   [CHG] Device 00:16:53:53:D3:19 Paired: yes
   Pairing successful

   [bluetooth]# quit
   ```

2. Start scratch-link python script.
    ```sh
    $ scratch_link
    ```

3. Connect scratch to micro:bit or Lego Mindstorms:
    * Open FireFox or Chrome and access [Scratch 3.0](https://scratch.mit.edu/)
    * Select the "Add Extension" button
    * Select the extension for your device (e.g., micro:bit or Lego Mindstorms EV3 extension) and follow the prompts to connect
    * Build your project with the extension blocks

In Case You Fail to Connect
---------------------------

1. If Scratch says "Make sure you have Scratch Link installed" but you are sure
   that scratch-link python script is running, check that Firefox or Chrome
   allows local server certificate.
    * Open Firefox or Chrome and access [https://device-manager.scratch.mit.edu:20110/](https://device-manager.scratch.mit.edu:20110/). You will see a security risk warning.
    * In **Firefox**: Click "Advanced" and click "Accept Risk and Continue".
    * In **Chrome**: type the special bypass keyword `thisisunsafe`.
    * Immediately, you will see "Failed to open a WebSocket connection". This is expected.

2. If device scan fails, check systemd bluetooth service status.
    ```
    systemctl status bluetooth.service
    ```
    * If the service is not working, refer guide of your distro to set it up.
    * If the service is working, also check that /etc/bluetooth/main.conf sets AutoEnable=true.

3. If scratch_link.py says "failed to connect to BT device: [Errno 13] Permission denied",
   make sure to pair the bluetooth device to your PC before connecting to Scratch.
