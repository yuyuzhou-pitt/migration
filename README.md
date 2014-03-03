migration
=========

This project is about vulnerable VM made host crash after migration.

----------------
Steps to get the diff to qemu-kvm-0.14.0+noroms (qemu-kvm-0.14.0+noroms.diff):

1. Download qemu-kvm_0.14.0+noroms.orig.tar.gz with below url and unpack it as the original version:

 https://launchpad.net/ubuntu/+source/qemu-kvm/0.14.0+noroms-0ubuntu4

2. Clean the compiled version src/qemu-kvm_0.14.0+noroms:

 $ make clean

3. Found the file with comments "jfp":

 $ grep -r 'jfp' ./* > ~/qemu-kvm-0.14.0+noroms-jfp.diff

4. Generate the diff file for each of the file with comments "jfp", and combine them to one diff file:

 $ ls qemu-kvm-0.14.0+noroms-*
 qemu-kvm-0.14.0+noroms-block-migration.diff  qemu-kvm-0.14.0+noroms-kvm-all.diff
 qemu-kvm-0.14.0+noroms-exec.diff             qemu-kvm-0.14.0+noroms-migration.diff
 qemu-kvm-0.14.0+noroms-helper.diff           qemu-kvm-0.14.0+noroms-monitor.diff
 qemu-kvm-0.14.0+noroms-hw-mc146818rtc.diff   qemu-kvm-0.14.0+noroms-savevm.diff
 qemu-kvm-0.14.0+noroms-jfp.diff              qemu-kvm-0.14.0+noroms-target-i386-helper.c

 $ cat qemu-kvm-0.14.0+noroms-*diff > qemu-kvm-0.14.0+noroms.diff 
 
----------------
Steps to get the diff to kernel v3.0 (linux-3.0-joe.diff):

1. Clone kernel source into local directory: 

 $ git clone https://github.com/torvalds/linux

2. Check into the tag v3.0

 $ cd linux/

 $ git tag

 $ git checkout -b bv3.0 v3.0

 $ git branch

 * bv3.0

   master

3. Clean the compiled directory: linux-3.0-joe/

 $ make clean

 $ rm cscope.files

 $ rm cscope.out

3. Diff the two directories:

 $ diff -Nurp linux/ linux-3.0-joe/ > linux-3.0-joe.diff

----------------
Steps to get diff to virtunoid (nelhage-virtunoid-joe.diff):

1. Clone virtunoid into local directory:

 $ git clone https://github.com/nelhage/virtunoid

2. Clean the compiled directory nelhage-virtunoid-joe/ to remove all the binary files.

3. Diff the two directories:

 $ diff -Nurp virtunoid/ nelhage-virtunoid-joe > nelhage-virtunoid-joe.diff

----------------
Steps to get diff to qemu-kvm (qemu-kvm-joe.diff):

1. Download qemu-kvm_0.14.0+noroms.orig.tar.gz:

 $ https://launchpad.net/ubuntu/+archive/primary/+files/qemu-kvm_0.14.0%2Bnoroms.orig.tar.gz

2. Clean the compiled directory qemu-kvm-0.14.0+noroms/ to remove all the binary files.

3. Diff the two directories:

 $ diff -Nurp qemu-kvm-0.14.0+noroms.orig/ qemu-kvm-0.14.0+noroms/ > qemu-kvm-joe.diff
