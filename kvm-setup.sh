# This contains a collection of commands to use for setting up KVM for building Virtual Machine on a Linux device
#
# BELOW INFO WAS COMPLETED USING THE BELOW OS
# uname -a
#Linux toborrocky-osbornepro-com 5.14.0-570.18.1.el9_6.x86_64 #1 SMP PREEMPT_DYNAMIC Fri May 30 18:43:28 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
#
# cat /etc/os-release 
#NAME="Rocky Linux"
#VERSION="9.6 (Blue Onyx)"
#ID="rocky"
#ID_LIKE="rhel centos fedora"
#VERSION_ID="9.6"
#PLATFORM_ID="platform:el9"
#PRETTY_NAME="Rocky Linux 9.6 (Blue Onyx)"
#ANSI_COLOR="0;32"
#LOGO="fedora-logo-icon"
#CPE_NAME="cpe:/o:rocky:rocky:9::baseos"
#HOME_URL="https://rockylinux.org/"
#VENDOR_NAME="RESF"
#VENDOR_URL="https://resf.org/"
#BUG_REPORT_URL="https://bugs.rockylinux.org/"
#SUPPORT_END="2032-05-31"
#ROCKY_SUPPORT_PRODUCT="Rocky-Linux-9"
#ROCKY_SUPPORT_PRODUCT_VERSION="9.6"
#REDHAT_SUPPORT_PRODUCT="Rocky Linux"
#REDHAT_SUPPORT_PRODUCT_VERSION="9.6"

# Install required packages
sudo dnf install -y epel-release
sudo dnf install -y qemu-kvm libvirt virt-manager virt-install bridge-utils virt-top libguestfs-tools bridge-utils virt-viewer 

# Verify kvm module is loaded
sudo lsmod | grep kvm

# Tell libvirt service to start automatically and to start
sudo systemctl enable --now libvirtd
# Verify the service is running
systemctl status libvirtd

# Add system user to the KVM group
sudo usermod -aG libvirt $USER

# Create Network Bridge for KVM instances
# By default a network bridge with the name virbr0 is created for NAT
# VMs using this bridge do not have external network access
brctl show
# For external connections we need to create a network bridge
# View interfaces
# nmcli connection show 
#NAME                UUID                                  TYPE      DEVICE 
#Wired connection 1  6418b003-7878-4cb3-9880-b2fcddacf906  ethernet  enp5s0 
#lo                  d57311b9-a8a3-46af-be55-6c12b932bbd8  loopback  lo     
#virbr0              45af469e-626d-4a55-9e70-10cc4f7ee379  bridge    virbr0 

# Define variables for the bridge connection
BR_NAME="br0"
BR_INT="$(ip route get 1.1.1.1 | awk '{print $5}')"
SUBNET_IP="$(hostname -I | cut -f1 -d' ')/24"
GW="$(ip route | awk '/default/ {print $3}')"
DNS1="1.1.1.2"
DNS2="1.0.0.2"
# Allow forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p
# Verify value. If not what you expect modify `vim /etc/sysctl.conf'
sysctl net.ipv4.ip_forward

# Create the new internface bridge
sudo nmcli connection add type bridge autoconnect yes con-name ${BR_NAME} ifname ${BR_NAME}
#Connection 'br0' (be72a118-aa39-439b-ac11-e5645bfadcc7) successfully added.
#
nmcli con show
#NAME    UUID                                  TYPE      DEVICE 
#enp5s0  6418b003-7878-4cb3-9880-b2fcddacf906  ethernet  enp5s0 
#br0     6b5e075d-259a-4b74-a9bb-a3796fe4dc39  bridge    br0    
#lo      d57311b9-a8a3-46af-be55-6c12b932bbd8  loopback  lo     
#virbr0  45af469e-626d-4a55-9e70-10cc4f7ee379  bridge    virbr0 

# Rename Wired connection 1
sudo nmcli con modify ${BR_INT} connection.id ${BR_INT}
sudo nmcli con down ${BR_INT} && sudo nmcli con up ${BR_INT}
sudo systemctl restart NetworkManager

# Configure the new br0 interface
sudo nmcli connection modify ${BR_NAME} ipv4.addresses ${SUBNET_IP} ipv4.method manual
sudo nmcli connection modify ${BR_NAME} ipv4.gateway ${GW}
sudo nmcli connection modify ${BR_NAME} ipv4.dns ${DNS1} +ipv4.dns ${DNS2}

# Make your main interface a slave to the bridge
sudo nmcli connection delete ${BR_INT}
#Connection 'Wired connection 1' (4555eaba-663a-4fec-a42c-5da716a7e859) successfully deleted.
nmcli con show
#NAME    UUID                                  TYPE      DEVICE 
#br0     6b5e075d-259a-4b74-a9bb-a3796fe4dc39  bridge    br0    
#lo      d57311b9-a8a3-46af-be55-6c12b932bbd8  loopback  lo     
#virbr0  45af469e-626d-4a55-9e70-10cc4f7ee379  bridge    virbr0 

sudo nmcli connection add type bridge-slave autoconnect yes con-name ${BR_INT} ifname ${BR_INT} master ${BR_NAME}
#Connection 'Wired connection 1' (7c8fbe0e-a23e-4329-9dad-55a7f405f5ea) successfully added.
nmcli con show
#NAME    UUID                                  TYPE      DEVICE 
#enp5s0  cbcc99e1-c051-4a56-8f64-5dcbbe94786d  ethernet  enp5s0 
#br0     6b5e075d-259a-4b74-a9bb-a3796fe4dc39  bridge    br0    
#lo      d57311b9-a8a3-46af-be55-6c12b932bbd8  loopback  lo     
#virbr0  45af469e-626d-4a55-9e70-10cc4f7ee379  bridge    virbr0 

# Start the bridge connection
sudo nmcli connection up br0
#Connection successfully activated (controller waiting for ports) (D-Bus active path: /org/freedesktop/NetworkManager/ActiveConnection/6)

# Verify it works
ping -I br0 1.1.1.1
#PING 1.1.1.1 (1.1.1.1) from 10.0.0.244 br0: 56(84) bytes of data.
#64 bytes from 1.1.1.1: icmp_seq=1 ttl=55 time=13.0 ms
#64 bytes from 1.1.1.1: icmp_seq=2 ttl=55 time=12.2 ms
# NOTE: If this ping fails delete the br0 internface and your starting interface. Then start these commands over
# nmcli con del br0 && nmcli con del ${BR_INT}
# Then in the desktop interface go up to the network icon and click Connect. This will get you connected to the internet again. Once that happens start this process over

# Configure the bridge interface
echo 'allow all' > /etc/qemu-kvm/bridge.conf
sudo systemctl restart libvirtd

# Set permissions for libvirt directory to use your setup qemu connection
sudo chown -R $USER:libvirt /var/lib/libvirt/

# If you have exernal storage for vms map it
# In your /etc/fstab file you should have something similar to these entries for your external drives
#/dev/sdd1 /mnt/vm_hosts     xfs     defaults        0 2
#/dev/sdb1 /mnt/iso_storage  ext4    defaults        0 2
rm -rf /var/lib/libvirt/images # Delete the current folder so you can create your symlink
ln -s /mnt/vm_hosts /var/lib/libvirt/images # Where vm hosts get created
# If you have an external drive you save ISOs on I also did the below for accessibility
ln -s /mnt/iso_storage /var/lib/libvirt/iso_storage
sudo chmod 666 /var/lib/libvirt/iso_storage/*

# Command to create an image though GUI may be recommended
cd /var/lib/libvirt
# Make Alma VM from an ISO
virt-install \
  --name AlmaLinux10 \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/almalinux-10.img,size=40,format=qcow2 \
  --os-variant centos-stream9 \
  --network bridge=br0,model=virtio \
  --graphics vnc,listen=0.0.0.0 \
  --console pty,target_type=serial \
  --location /var/lib/libvirt/iso_storage/AlmaLinux-10.0-x86_64-dvd.iso

# Make Ubuntu VM from a live ISO
virt-install \
  --name Ubuntu24 \
  --ram 3072 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/ubuntu-24.04.02.img,size=40,format=qcow2 \
  --os-variant ubuntu24.04 \
  --network bridge=br0,model=virtio \
  --graphics vnc,listen=0.0.0.0 \
  --console pty,target_type=serial \
  --cdrom /var/lib/libvirt/iso_storage/ubuntu-24.04.2-live-server-amd64.iso

#===================
# WINDOWS DEVICES
#===================
# IMPORTANT: Your Windows server will not have a NIC when you first boot it
# To get internet to your Windows Server image you will need to
# 1.) Open Device Manager
# 2.) Right click on the drivers with a Warning icon over them that are unknown and select Update Drivers
# 3.) Select Search my Computer for Updates
# 4.) Select the moutned virtio drive (usually E drive)
# 5,) Now they have internet

# Make Windows Server 2022 from ISO
cd /var/lib/libvirt/iso_storage
wget https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
cd ..
virt-install \
  --name WinServer2022 \
  --ram 4096 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/winserver2022.img,size=50,format=qcow2 \
  --os-variant win2k22 \
  --network bridge=br0,model=virtio \
  --graphics vnc,listen=0.0.0.0 \
  --console pty,target_type=serial \
  --cdrom /var/lib/libvirt/iso_storage/WindowsServer2022_x64FRE_en-us.iso \
  --disk path=/var/lib/libvirt/iso_storage/virtio-win.iso,device=cdrom

# Make Windows Server 2025 from ISO
cd /var/lib/libvirt/iso_storage
wget https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
cd ..
virt-install \
  --name WinServer2025 \
  --ram 4096 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/winserver2025.img,size=50,format=qcow2 \
  --os-variant win2k22 \
  --network bridge=br0,model=virtio \
  --graphics vnc,listen=0.0.0.0 \
  --console pty,target_type=serial \
  --cdrom /var/lib/libvirt/iso_storage/WindowsServer2025_x64FRE_en-us.iso \
  --disk path=/var/lib/libvirt/iso_storage/virtio-win.iso,device=cdrom
