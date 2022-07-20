#!/usr/bin/env python
    
import usb.core
import usb.util


def main():
	dev = usb.core.find(find_all=True)
	for d in dev:
		print(usb.util.get_string(d,128,d.iManufacturer))
	
if __name__ == '__main__':
	main()