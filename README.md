# Linux
### The Utopia Linux kernel distribution

# About

Utopia uses the Linux kernel, however, the Linux kernel used by Utopia is a special one, compared to a "stock" image of the Linux kernel, our kernel:

- Enables Mach-O support: The default format for executables in Utopia is Mach-O, a format mostly found on Apple operating systems. It brings advantages such as two level namespaces, symbol reexporting and FAT binaries!

- Enables UtopiaHide: Utopia uses a non standard file hiearchy, in order to survive along the legacy tree, Utopia hides old directories from the user, using a kernel level patch.

- Enables DNASC: Certain directories are protected in a SIP-like way, Definitely Not A SIP Copy allows the user (and the system) to set which directories should be read only. This permission is a kernel level permission, so not even the root user can modify directories in this registry.

- Enables Mach Communication: Utopia has support for Mach ports, which are essential for Utopia's init system.

The kernel is based on the latest Linux LTS, rolling kernels are not recommended, but we can't say they aren't supported.

# Development and hacking

Since this kernel is just a fork of the standard Linux kernel, most of the articles about Linux kernel hacking will apply here.

This repository contains the kernel, patches, scripts and files used by our configuration.

## About the file tree

- configs: Contains our default configurations, each one of these is documented later on.
- framework_bash: Our scripts use a bash framework that enables features that other modern programming language have.
- patches: This folder contains our patch files, is pretty self explanatory
- scripts: Scripts contains two important players `import-src.sh` and `patch.sh` their functionality is documented below.
- src: The patched Linux kernel source
- utopia: Utopia source files that are added to the Linux kernel.

## Configs

The Linux kernel supports certain configurations, which enable or disable certain kernel features.

The Utopia kernel includes pre-made configuration files, these configurations ensure that the default components needed by the Utopia userland are loaded on the Kernel.

Depending on your use case, certain configuration might be required:

- BasicUtopia: Basic Console, Mach-O files, Kernel debbuging and 64 bit kernel, recommended for quick development sessions in Qemu.

## Updating the source

When a new Linux-LTS version is release, is recommended to update the source code.

In order to update the source code, you will need to have the following packages installed:
- bash
- jq
- grep
- awk
- cat
- xz
- gzip
- tar

Once all the programs are installed, you should be able to update the source code by following the next steps:
1. Open config.json, and change the corresponding version and sha256 filesum
2. Run `./scripts/import-src.sh`
3. Run `./scripts/patch.sh`


## Building

Building the Utopia kernel, is easy and straight forward, as the process isn't that different from building an stock Linux kernel.

You might want to have the following programs installed or the following files availible:
- Linux kernel headers
- Ncurses development library
- Flex
- GCC
- Bison
- Binutils
- Patch

Once everything is installed, proceed by creating a "build" folder.

Once that's done, is recommend to setup a Bash env variable, named `WORKSPACE` with the following value: `WORKSPACE=$(realpath .)`

After you created the "build" folder, copy the configuration you want to build Utopia with to the "build" folder, using the following command `cp $WORKSPACE/Configs/BasicUtopia $WORKSPACE/build/.config` this should set the default configuration.

After you're done, `cd` into the "src" directory, and type `make O=$WORKSPACE/build -j$(nproc)`

You're done!