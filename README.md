OptimizeVM
==========

Make Windows VMs Faster

## What is this?

Do you make Windows development VMs? Are they slow? This script will make them fast(er). 

OptimizeVM is based on the (VMware View Optimization Guide)[http://www.vmware.com/files/pdf/VMware-View-OptimizationGuideWindows7-EN.pdf].

OptimizeVM will remove Windows features that fequently access disk and stress the graphics subsystem that are probably useless in VMs.
For exmaple, Windows Updates, System Restore, and Registry Backup are unnecessary in VMs that are regularly restorted to a snapshot.

The script comments have more details about what exactly is changed.

OptimizeVM is not provied by, nor endorsed by, nor affiliated with VMware, Inc.

## Usage

From an elevated command prompt, run `OptimizeVM.bat`.

All actions are logged to `OptimizeVM.log`.

Defragment the VM's disk.

**Restart the VM**

## License 

This software is licensed under the MIT License
