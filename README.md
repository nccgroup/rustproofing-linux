# Rustproofing Linux (Porting Linux Kernel Bugs to Rust)

This source code repository is a collection of examples accompanying the blog post at <https://research.nccgroup.com/?p=18577>.

DO NOT USE these examples for anything but following the blog post. They intentionally contain vulnerabilities, and even the "fixed" versions might contain bugs.

If you wish to run the examples from the blog post, the following guidelines should hopefully make it easy to do so.


## Get dependencies

Get Rust for Linux source code. You might need to install some dependencies listed on [https://github.com/Rust-for-Linux/linux/blob/rust/Documentation/rust/quick-start.rst](the quick start page) .

```
git clone https://github.com/Rust-for-Linux/linux rust-for-linux
cd rust-for-linux
git checkout bd123471269354fdd504b65b1f1fe5167cb555fc  # latest commit at the point of writing
```


Get virtme. You might also need to install QEMU and some other dependencies.

```
git clone https://github.com/amluto/virtme
```

I find virtme really useful for quickly testing a change in either core kernel or a kernel module.


## Compile the kernels

Build kernel base most examples will run on:

```
cd rust-for-linux
mkdir `pwd`.out
cp ../rustproofing-linux/configs/config-base `pwd`.out/.config
KBUILD_OUTPUT=`pwd`.out make -j$(nproc) LLVM=1
```

And variants with slightly different config options:

```
mkdir `pwd`.out.ovf
cp `pwd`.out/.config `pwd`.out.ovf
scripts/config --file `pwd`.out.ovf/.config -d CONFIG_RUST_OVERFLOW_CHECKS
KBUILD_OUTPUT=`pwd`.out.ovf make -j$(nproc) LLVM=1

mkdir `pwd`.out.stackinit
cp `pwd`.out/.config `pwd`.out.stackinit
scripts/config --file `pwd`.out.stackinit/.config -e CONFIG_INIT_STACK_ALL_ZERO
KBUILD_OUTPUT=`pwd`.out.stackinit make -j$(nproc) LLVM=1
```


## Running a built kernel

Use the following command to start the built kernel inside QEMU:

```
../virtme/virtme-run --kdir `pwd`.out --show-command --show-boot-console --mods=auto -a "kasan_multi_shot" --qemu-opts -cpu core2duo -m 1G -smp 2
```

Change the `--kdir` option when you need to run the other two kernels.

The modules are then compiled with following command. Note that `KDIR` needs to point to the directory with compiled kernel, and that you will need to recompile for `../rust-for-linux.out.stackinit` and `../rust-for-linux.out.ovf` when testing examples that require differently compiled kernels.

```
cd ../rustproofing-linux
make LLVM=1 KDIR=../rust-for-linux.out
```

Modules are loaded and proof-of-concept exploits are ran with help of `test.sh` script. Examples are found in the blog post.
