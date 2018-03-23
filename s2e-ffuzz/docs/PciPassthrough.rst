===============================
Using Real PCI Devices with S2E
===============================

.. contents::

Setting up the Host
===================

You need:

* Intel VT-d (IOMMU)
* A recent Linux kernel (3.12 or later, earlier versions might cause kernel panics)
* Add ``intel_iommu=on`` to the boot parameters

Launching S2E
=============

::

  #Initialize the passthrough driver
  modprobe vfio_pci

  #Ethernet NIC on the Lenovo W520 (use ``lspci -vv`` to find where the device is plugged in)
  DEVICE=00:19.0
  
  #See Documentation/vfio.txt in the kernel source for more info about this
  echo "8086 1502" > /sys/bus/pci/drivers/vfio-pci/new_id

  #This needs root, unless you grant the permissions to devices in /dev/vfio/  
  sudo $QEMU -m 512 -boot c -net user -hda image.raw.s2e -device vfio-pci,host=$DEVICE


Quirks
======

* ``intel_iommu=on`` floods the syslog with a ton of errors, slowing down the system
  This happens, e.g., on a Lenovo W520 laptop. Some devices poke memory without having
  the rights for that. Identify the device and disable it in the BIOS (e.g., the FireWire
  port in the case of the Lenovo).

* The device is left in a metastate and doesn't seem to work anymore after S2E is closed.
  The following appears in the syslog:

  ::

     $ sudo modprobe e1000e
     $ dmesg | tail -n 6
     [100860.732579] e1000e: Intel(R) PRO/1000 Network Driver - 2.1.4-k
     [100860.732588] e1000e: Copyright(c) 1999 - 2012 Intel Corporation.
     [100860.732659] e1000e 0000:00:19.0: setting latency timer to 64
     [100860.732861] e1000e 0000:00:19.0: Interrupt Throttling Rate (ints/sec) set to dynamic conservative mode
     [100860.732952] e1000e 0000:00:19.0: irq 55 for MSI/MSI-X
     [100860.832252] e1000e: probe of 0000:00:19.0 failed with error -3

  Solution:

  ::

    rmmod vfio_iommu_type1 vfio_pci vfio
    sleep 1

    echo 1 > /sys/bus/pci/devices/0000:00:19.0/reset
    sleep 1

    echo 1 > /sys/bus/pci/devices/0000:00:19.0/remove
    sleep 1

    #Here, suspend the machine, and turn it back on.
    #It should reset the device properly.

    echo 1 > /sys/bus/pci/rescan
    sleep 1

    sudo modprobe e1000e
    dmesg | tail -n 10

