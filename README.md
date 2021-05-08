# pyscrlink

Pyscrlink is a [Scratch-link](https://github.com/LLK/scratch-link) for Linux.
Scratch-link is a software module which connects
[Scratch](https://scratch.mit.edu/) to Bluetooth devices such as
[micro:bit](https://microbit.org/). However, as of October 2020, it only works
on Windows and MacOS, and Linux operating systems can not connect Scratch and
micro:bit.

Pyscrlink allows you to connect Scratch and bluetooth devices with the Linux
OSes. It uses the Linux Bluetooth protocol stack [Bluez](http://www.bluez.org/)
and its python interfaces [pybluez](https://github.com/pybluez/pybluez) to
handle Bluetooth, and [bluepy](https://github.com/IanHarvey/bluepy) to handle
Bluetooth Low Energy (BLE) connections. It has been reported that pyscrlink
connects Scratch 3.0 with micro:bit, LEGO Mindstorms EV3, LEGO WeDo, LEGO
Boost, Intelino Smart Train and toio.

To use websockets, pyscrlink requires python version 3.6 or later. If your
system has python older than version 3.6, install newer version. If your
system has python 3 explicit command names python3 and pip3, use them in the
steps below.

Pyscrlink was launched in 2019 as "bluepy-scratch-link". This was a small task
dedicated to micro:bit and bluepy for BLE connection. After many contributions,
it expanded coverage to pybluez with other devices for Bluetooth connectivity.
It was misleading that the name "bluepy-scratch-link" indicates that it depends
only on bluepy. As of October 2020, name of the project has been changed from
"bluepy-scratch-link" to "pyscrlink" to avoid confusion.

Confirmed Environments
----------------------
The instructions below was confirmed with following devices and distros.
Trial with other distros and feed-backs will be appreciated.

Pyscrlink was confirmed with following devices, Linux distros and browsers.

Devices:
* micro:bit

Linux distros:
* Arch Linux
* elementary OS 5.1 Hera

Browsers:
* FireFox
* Chromium

It was reported that pyscrlink (former bluepy-scratch-link) working with
following devices and Linux distros.

Devices:
* LEGO Mindstorm EV3 by @chrisglencross
* LEGO WeDo by @zhaowe, @KingBBQ
* LEGO Boost by @laurentchar, @miguev, @jacquesdt
* Intelino Smart Train by @ErrorJan
* toio by @shimodash

Linux distros:
* Raspbian by @chrisglencross
* Ubuntu 16.04 @jacquesdt
* Ubuntu Studio 20.04 @miguev

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
    $ sudo apt install bluez libbluetooth-dev libnss3-tools libcap2-bin libglib2.0-dev
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
    * Flash the micro:bit over USB with the Scratch Hex File, you will see the
      five character name of the micro:bit scroll across the screen such as
      'zo9ev'.

Usage
-----
1. For LEGO Mindstorms EV3, pair your Linux PC to the EV3 brick.

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

3. Connect scratch to the target device such as micro:bit or LEGO Mindstorms:
    * Open FireFox or Chrome. (Make sure to run as the same user for scratch-link python script.)
    * Access [Scratch 3.0](https://scratch.mit.edu/) and create your project.
    * Select the "Add Extension" button.
    * Select the extension for your device (e.g., micro:bit or Lego Mindstorms EV3 extension) and follow the prompts to connect.
    * Build your project with the extension blocks.

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

4. To connect to multiple devices at the same time, make all the target devices
   ready for scan at the first device scan. This is important for toio. The toio
   allows a single project to connect to two toio devices.
   * When the second device was prepared after the first device was connected, device scan can not find the second device.
   * To scan and find the second device, disconnect connections for the first device beforehand.

Issus Reporting
---------------

Please file issues to [GitHub issue tracker](https://github.com/kawasaki/pyscrlink/issues).

Releases
--------

Release 0.2.3

* Fixed eternal loop caused by hostname resolve failure

Release 0.2.2

* Supported multiple device connections for toio
* Improved session closure handling

Release 0.2.1

* Added libglib to required package list in README.md
* Improved setcap and getcap tool finding

Release 0.2.0

* Latency issue fix for BLE devices' write characteristics

Release 0.1.0

* Initial release
