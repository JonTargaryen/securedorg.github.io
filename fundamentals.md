---
layout: default
permalink: /RE101/section1/
title: Fundamentals
---
[Go Back to Reverse Engineering Malware 101](https://securedorg.github.io/RE101/)

# Section 1: Fundamentals #

## Environment Setup ##

In this section you will be setting up a safe virtual malware analysis environment. The virtual machine (VM) that you will be running the malware on should not have internet access nor network share access to the host system. This VM will be designated as the **Victim VM**. On the other hand, the **Sniffer VM** will have a passive role in serving and monitoring the internet traffic of the Victim VM. This connection remains on a closed network within virtualbox.

### Installing VirtualBox ###

For windows and osx, follow the instructions in the install binary.

| Windows | Mac OSX | Linux |
| --- | --- | --- |
| [![alt text](https://securedorg.github.io/images/VBwin.png "Windows Virualbox")](http://download.virtualbox.org/virtualbox/5.1.14/VirtualBox-5.1.14-112924-Win.exe) | [![alt text](https://securedorg.github.io/images/VBmac.png "OSX Virtualbox")](http://download.virtualbox.org/virtualbox/5.1.14/VirtualBox-5.1.14-112924-OSX.dmg) | [![alt text](https://securedorg.github.io/images/Vblinux.png "Linux Virtualbox")](https://www.virtualbox.org/wiki/Linux_Downloads) |

### Download Victim and Sniffer VMs ###

Please use the utility [7zip](http://www.7-zip.org/download.html). Unzip the files with 7zip below and in VirtualBox **File->Import** Appliance targeting the .ova file. 


[Victim VM](https://drive.google.com/open?id=0B_0DJl2kuzoNZkpveEtiMWJKWDA)

* MD5sum: 7d4f2ff359cd74eec3cae7b16a916939 **Updated 6/30/2017**
* Source: [Microsoft Free VirtualBox VMs](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
* OS: Windows 7 Service Pack 1
* Architecture: Intel 32bit
* Username: victim
* Password: re1012017
* IP Address: 192.168.0.2
* Gateway: 192.168.0.1
* Zip size 3.7G, Final size required 10G


[Sniffer VM](https://drive.google.com/open?id=0B_0DJl2kuzoNT3IwNElLV3VRdms)

* MD5sum: f9c9214475560ab0b019654560e9d3b8 **Updated 6/30/2017**
* OS: Ubuntu 16.04.2 LTS Desktop
* Architecture: Intel 64bit
* Username: sniffer
* password re1012017
* IP Address: 192.168.0.1
* Gateway: 192.168.0.1
* Zip size 1.9G, Final size required 6G

---

### Post Install Instructions ###

1. Install VirtualBox CD on both VMs: Devices->Insert Guest Additions CD Image. For VMware Tools: VM->Install VMware Tools from the VMware Workstation menu
  * If it doesn't auto appear, navigate to the CD Drive to install
  * Follow install directions from the Guest Additions Dialog
  * Note: it will require install privileges so insert passwords for each VM
  * Shutdown Both VMs after you have installed the Guest Additions CD or VM Tools CD
2. Victim VM: 
  * Vbox: Devices->Drag and Drop->Bidrectional
  * VMware: Virtual Machine Settings->Guest isolation. Enable drag and drop to and from this virtual machine.
3. Victim VM: 
  * Vbox: Devices->Shared Clipboard->Bidirectional
4. Both VMs: 
  * Vbox: Devices->Network->Network Settings
    * Select Attached to `Internal Network`
    * Name should mirror both VMs. Default is `intnet`
  * Vmware: Virtual Machine Settings->Network, add a NAT network such as VMnet8.
    * Name should mirror both VMs.
5. Run/Play both VMs to verify network connectivity
  * **Important** While running, take a snapshot of each VM and name each "Clean". This will save a clean slate for you to revert the VM image back to.
6. Sniffer VM: Ensure `inetsim` is running
  * Open terminal and run: `ps -ef | grep inetsim`
  * If no output, run: `/etc/init.d/inetsim start`
  * Run the ps command again to confirm it's running.
  * Expected output: ![alt text](https://securedorg.github.io/images/VerifyInetsim.png "ps output")
7. Victim VM: test connection to Sniffer VM
  * In the search bar, type `cmd.exe` to open terminal
  * Run command: `ping 192.168.0.1`
  * Expected output: ![alt text](https://securedorg.github.io/images/PingGateway.png "Ping Output")
8. Sniffer VM: Devices->Shared Folders->Shared Folders Settings
  * On your Host, create a folder called `sniffershare`
  * In virtual box select Add New Shared Folder icon and navigate to the folder you just created (sniffershare)
  * In Sniffer VM, open the terminal and run command:`mkdir ~/host; sudo mount -t vboxsf -o uid=$UID,gid=$(id -g) sniffershare ~/host`

[Intro <- Back](https://securedorg.github.io/RE101/intro) | [Next -> Anatomy of PE](https://securedorg.github.io/RE101/section1.2)
