# PiHost
## Match IP addresses to hostnames in PiHole

Pihole is great, but the admin interface only displays device details 
by IP address which can be confusing. This script changes the display
from IP address to a more recognizable hostname. And as a bonus, attaches
the profile (from fingerbank.org) of the device to the hostname as well - 
so instead of something like 192.168.1.101, you see galaxys6__samsung.

## Setup

You'll need to install some python packages for pihost.

    sudo pip3 install pip --upgrade
    sudo pip3 install python-hosts
    sudo pip3 install urllib3
    sudo pip3 install requests

And you will also need tcpdump

    sudo apt-get install tcpdump

and then we need scapy

    git clone https://github.com/secdev/scapy
    cd scapy
    sudo python3 setup.py install

## API KEY

You will need to update secrets.py with your API Key. Secrets.py contanis one
line only:

API_KEY = "<Insert your key here>"

You're goning to run into problems without this file / key. You can get your 
own API KEY from Fingerbank.

### Fingerbank

PiHost will query fingerbank to get a profile of devices on the network.
This allows us to appent useful info to the device name to help identify
what we're looking at in the PiHole console. Head on over to fingerbank.org
and creat a free account. Once that's done you'll need to get your API key
from the 'My Account' section.

## Usage

sudo python3 pihost.py

This will run pihost in the console. You'll be able to see DHCP queries coming in
and be able to confirm everything is working as expected.

## Launching PiHost at startup

In order to have a command or program run when the Pi boots, you can add commands
to the rc.local file. Edit the file /etc/rc.local using the editor of your choice.
You must edit it with root permissions:

    sudo vi /etc/rc.local

Add the command to launch PiHost at startup. Make sure to use the absolute reference
to the file.

    sudo python3 /home/pi/pihost.py &

IMPORTANT: Don't forget the '&' at the end. This will fork the process and allow
booting to continue. Without this the system would wait for this process to
complete before continuing to boot. Because PiHost keeps looping and never stops
sniffing for DHCP packets the boot process would be waiting indefinatly.