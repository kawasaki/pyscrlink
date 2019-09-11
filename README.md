# bluepy-scratch-link

Bluepy-scratch-link is [Scratch-link](https://github.com/LLK/scratch-link)
implemented on bluepy as a small python script. As of October 2019, Scratch-link
is a software module which connects [Scratch](https://scratch.mit.edu/) and
Bluetooth devices such as [micro:bit](https://microbit.org/). However, it works
only on Windows and MacOS, and cannot connect Scratch and micro:bit on Linux.

Bluepy-scratch-link allows Linux PCs to connect Scratch and micro:bit. It uses
Linux Bluetooth protocol stack [Bluez](http://www.bluez.org/) and its python
interface [bluepy](https://github.com/IanHarvey/bluepy) to handle Bluetooth Low
Energy, or BLE, connections with micro:bit. It is confirmed that
bluepy-scratch-link connects Scratch 3.0 and a micro:bit.

This is a minimal implementation to support micro:bit. Some of Scratch-link
features are not implemented. For example, Bluetooth (non-BLE) devices are not
supported. BLE device support other than micro:bit is not confirmed.

Bluepy-scratch-link is for python 3 and do not work for python 2. If your Linux
system has explicit command names python3 and pip3, use them in the instructions
below.

The instructions below was confirmed with elementary OS 5.0 Juno which is
based on Ubuntu 18.04 LTS and Arch Linux. Trial with other distros and
feed-backs will be appreciated.

Installation
------------
1. Prepare BLE controller
   Confirm that your Linux PC has a Bluetooth controller with BLE support.
   Bluetooth 4.0 controller supports BLE. If your PC does not have it, need
   to plug USB Bluetooth 4.0 adapter.

2. Install Bluez package
    ```sh
    Ubuntu
    $ sudo apt install bluez
    Arch
    $ sudo pacman -S bluez
    ```

3. Install python modules
    ```sh
    $ sudo pip install bluepy websockets
    Or if your system has python3 command,
    $ sudo pip3 install bluepy websockets
    ```

4. Get bluepy-scratch-link
   Example below installs bluepy-scratch-link under your home directory.
    ```sh
    $ cd ~
    $ git clone git@github.com:kawasaki/bluepy-scratch-link.git
    ```

5. Prepare web server certificate
    Scratch-link requires local Secure WebSocket server with certificate.
    Generate and prepare a PEM certificate file.
    ```sh
    $ cd ~/bluepy-scratch-link
    $ openssl req -x509 -out scratch-device-manager.cer \
    -keyout scratch-device-manager.key -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=scratch-device-manager' -extensions EXT -config <( \
    printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
    $ openssl pkcs12 -inkey scratch-device-manager.key \
      -in scratch-device-manager.cer \
      -name "Scratch Link & Scratch Device Manager" \
      -passout pass:Scratch -export -out scratch-device-manager.pfx
    $ grep -h ^ scratch-device-manager.cer scratch-device-manager.key \
      | tr -d '\r' > scratch-device-manager.pem
      ```

6. Install Scratch-link hex in micro:bit
    * Download and unzip the [micro:bit Scratch Hex file](https://downloads.scratch.mit.edu/microbit/scratch-microbit-1.1.0.hex.zip).
    * Flash the micro:bit over USB with the Scratch .Hex File, you will see the
      five character name of the micro:bit scroll across the screen such as
      'zo9ev'.

Usage
-----
1. Turn on Bluetooth Low Energy controller
    ```sh
    $ sudo btmgmt le on
    $ sudo btmgmt power on
    ```

2. Start scratch-link python script
    ```sh
    $ cd ~/bluepy-scratch-link
    $ sudo ./scratch_link.py
    Or if your system has python3 command,
    $ sudo python3 ./scratch_link.py
    ```

3. Start Firefox and allow local server certificate
    * Open firefox and open [https://device-manager.scratch.mit.edu:20110/](https://device-manager.scratch.mit.edu:20110/). You will see security risk warning.
    * Click "Advanced" and click "Accept Risk and Continue". Your will see
      "Failed to open a WebSocket connection". This is expected.
    * This action is required only the first time to access.
    * Note: it is not known how to allow Chrome to accept self signed
      certificate.

4. Connect scratch to micro:bit
    * Open [Scratch 3.0](https://scratch.mit.edu/)
    * Select the "Add Extension" button
    * Select micro:bit extension and follow the prompts to connect micro:bit
    * Build your project with the extension blocks
