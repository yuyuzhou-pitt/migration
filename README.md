migration
=========

This project is about vulnerable VM made host crash after migration.

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

