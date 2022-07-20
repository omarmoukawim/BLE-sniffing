// pip for python3
sudo python -m pip install --upgrade pip

// libUSB 1
sudo apt-get install libusb-1.0-0-dev

// pyUSB
pip install pyusb

cd /etc/udev/rules.d/
sudo nano  99-com.rules
// add line at the end of file:
SUBSYSTEMS=="usb", ENV{DEVTYPE}=="usb_device", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="16b3", GROUP="plugdev", MODE="0777"
// then
sudo udevadm control --reload
sudo udevadm trigger

// unplug aned replug dongle

// install six
pip install six

// vedere link:
https://github.com/pyusb/pyusb/blob/master/docs/tutorial.rst
https://revspace.nl/CC2540
https://github.com/christianpanton/ccsniffer/blob/master/ccsniffer.py
https://github.com/bertrik/cc2540
// l'applicazione eesniffer e' un mix da queste fonti
// l'applicazione ffSniffer è un unpgrade della eeSniffer

