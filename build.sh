#!/bin/bash

create_gpg_key() {
	rm -rf ./gnupg
	mkdir -p ./gnupg
	gpg --homedir ./gnupg --batch --passphrase '' --quick-gen-key TEST_USER_ID default default
	rm ./test_user_id.key
        gpg --homedir ./gnupg --output ./test_user_id.key --export
	cp ./test_user_id.key smi/base.part/
}

create_certificates() {
    pushd certs
    
    for f in kek.cnf  pca.cnf  root.cnf  uefi.cnf pkkek1.cnf ; do
       sed "s,XXX,$IDX," template/$f > $f 
    done
    
    openssl req -config ./root.cnf -new -x509 -newkey rsa:2048 -nodes -days 36500 -outform PEM -keyout Root.key -out Root.crt
    openssl req -config ./pkkek1.cnf -new -x509 -newkey rsa:2048 -nodes -days 36500 -outform PEM -keyout PkKek1.key -out PkKek1.crt
    
    openssl req -config ./uefi.cnf -nodes  -days 36500 -newkey rsa:2048 -keyout Uefi.key -out Uefi.csr
    openssl x509 -req -in Uefi.csr -CA Root.crt -CAkey Root.key -CAcreateserial -out Uefi.crt
    openssl x509 -inform PEM -in Uefi.crt -outform DER -out Uefi.cer
    
    openssl req -config ./pca.cnf -nodes  -days 36500 -newkey rsa:2048 -keyout Pca.key -out Pca.csr
    openssl x509 -req -in Pca.csr -CA Root.crt -CAkey Root.key -CAcreateserial -out Pca.crt
    openssl x509 -inform PEM -in Pca.crt -outform DER -out Pca.cer
    
    openssl req -config ./kek.cnf -nodes  -days 36500 -newkey rsa:2048 -keyout Kek.key -out Kek.csr
    openssl x509 -req -in Kek.csr -CA Root.crt -CAkey Root.key -CAcreateserial -out Kek.crt
    openssl x509 -inform PEM -in Kek.crt -outform DER -out Kek.cer
    
    popd
}

create_singer_ca() {
    rm -rf ./ca
    mkdir -p ./ca/uefi_sb_ca
     
    certutil -d ./ca/uefi_sb_ca -N --empty-password
     
    $EFIKEYGEN -d ./ca/uefi_sb_ca \
      --ca --self-sign \
      --nickname='Xiaoxin UEFI SB CA' \
      --common-name="C=CA,ST=Quebec,L=Montreal,O=Xiaoxin,CN=Xiaoxin UEFI SB CA $IDX" \
      --serial=00
     
    $EFIKEYGEN -d ./ca/uefi_sb_ca \
      --signer='Xiaoxin UEFI SB CA' \
      --nickname='Xiaoxin UEFI SB Signer' \
      --common-name="C=CA,ST=Quebec,L=Montreal,O=Xiaoxin,CN=Xiaoxin UEFI SB Signer $IDX" \
      --serial=01
     
    pk12util -d ./ca/uefi_sb_ca -o signer.p12 -n 'Xiaoxin UEFI SB Signer' -W 1234
     
    mkdir -p ./ca/uefi_sb_signer
    certutil -d ./ca/uefi_sb_signer -N --empty-password
    pk12util -d ./ca/uefi_sb_signer -i signer.p12 -W 1234
    shred signer.p12
    
    # xiaoxin-ca.cer will be used as vendoer certificate in shim
    certutil -d ./ca/uefi_sb_ca -L -n "Xiaoxin UEFI SB CA" -r > xiaoxin-ca.cer
}

build_edk () {
    pushd edk2 
    git submodule update --init

    rm -rf Build/
    # Replace AuthData.c
cat  <<EOF > ./OvmfPkg/EnrollDefaultKeys/AuthData.c
#include "EnrollDefaultKeys.h"

CONST UINT8 mMicrosoftKek[] = {
EOF
cat ../certs/Kek.cer  | od -t x1 | awk '{for(i=2;i<=NF;i++)printf("0x"$i", "); print ""}' >> ./OvmfPkg/EnrollDefaultKeys/AuthData.c

cat  <<EOF >> ./OvmfPkg/EnrollDefaultKeys/AuthData.c
};

CONST UINTN mSizeOfMicrosoftKek = sizeof mMicrosoftKek;


CONST UINT8 mMicrosoftPca[] = {
EOF
cat ../certs/Pca.cer  | od -t x1 | awk '{for(i=2;i<=NF;i++)printf("0x"$i", "); print ""}' >> ./OvmfPkg/EnrollDefaultKeys/AuthData.c
cat  <<EOF >> ./OvmfPkg/EnrollDefaultKeys/AuthData.c
};

CONST UINTN mSizeOfMicrosoftPca = sizeof mMicrosoftPca;

CONST UINT8 mMicrosoftUefiCa[] = {
EOF
cat ../certs/Uefi.cer  | od -t x1 | awk '{for(i=2;i<=NF;i++)printf("0x"$i", "); print ""}' >> ./OvmfPkg/EnrollDefaultKeys/AuthData.c
cat  <<EOF >> ./OvmfPkg/EnrollDefaultKeys/AuthData.c
};
CONST UINTN mSizeOfMicrosoftUefiCa = sizeof mMicrosoftUefiCa;

CONST UINT8 mSha256OfDevNull[] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
  0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
  0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

CONST UINTN mSizeOfSha256OfDevNull = sizeof mSha256OfDevNull;

EOF

    # Do not attempt to build BrotliCompress
    sed -i '/BrotliCompress/d' BaseTools/Source/C/GNUmakefile

    export PYTHON_COMMAND=/usr/bin/python3
    . edksetup.sh
    make -C BaseTools/

    # Remove BrotliCustomDecompressLib
    cp MdeModulePkg/MdeModulePkg.dec MdeModulePkg/MdeModulePkg.dec.orig
    tac MdeModulePkg/MdeModulePkg.dec.orig | sed '/BrotliCustomDecompressLib/I,+1 d' | tac > MdeModulePkg/MdeModulePkg.dec

    #build -n 40 --cmd-len=65536 -t GCC5 -b DEBUG --hash -D NETWORK_IP6_ENABLE -D NETWORK_HTTP_BOOT_ENABLE -D NETWORK_TLS_ENABLE -D TPM_ENABLE -D FD_SIZE_4MB -a X64 -D PVSCSI_ENABLE=FALSE -D MPT_SCSI_ENABLE=FALSE -p OvmfPkg/OvmfPkgX64.dsc

    build -D SECURE_BOOT_ENABLE -D EXCLUDE_SHELL_FROM_FD -n 40 --cmd-len=65536 -t GCC5 -b DEBUG --hash -D NETWORK_IP6_ENABLE -D NETWORK_HTTP_BOOT_ENABLE -D NETWORK_TLS_ENABLE -a IA32 -a X64 -p OvmfPkg/OvmfPkgIa32X64.dsc -D SMM_REQUIRE -D PVSCSI_ENABLE=FALSE -D MPT_SCSI_ENABLE=FALSE -D TPM_ENABLE -D FD_SIZE_4MB

    export MTOOLS_SKIP_CHECK=1
    rm -f uefi_shell.img
    $MKDOSFS -C uefi_shell.img -n UEFI_SHELL -- 2167
    mmd -i uefi_shell.img ::efi
    mmd -i uefi_shell.img ::efi/boot
    mcopy -i uefi_shell.img Build/Ovmf3264/DEBUG_GCC5/X64/Shell.efi ::efi/boot/bootx64.efi
    mcopy -i uefi_shell.img Build/Ovmf3264/DEBUG_GCC5/X64/EnrollDefaultKeys.efi ::/EnrollDefaultKeys.efi

    mdir -i uefi_shell.img -/ ::

    genisoimage -input-charset ASCII -J -rational-rock -efi-boot uefi_shell.img -no-emul-boot -o UefiShell.iso -- uefi_shell.img

    popd

    # Generate OVMF variables ("VARS") file with default Secure Boot keys enrolled
    sed \
        -e 's/^-----BEGIN CERTIFICATE-----$/4e32566d-8e9e-4f52-81d3-5bb9715f9727:/' \
        -e '/^-----END CERTIFICATE-----$/d' \
        certs/PkKek1.crt > PkKek1.oemstr

    rm -f OVMF_VARS.secboot.fd
    /usr/bin/python3 qemu-ovmf-secureboot/ovmf-vars-generator --verbose --verbose --qemu-binary $KVM --ovmf-binary edk2/Build/Ovmf3264/DEBUG_GCC5/FV/OVMF_CODE.fd --ovmf-template-vars edk2/Build/Ovmf3264/DEBUG_GCC5/FV/OVMF_VARS.fd --uefi-shell-iso edk2/UefiShell.iso --oem-string "$(< PkKek1.oemstr)" --skip-testing OVMF_VARS.secboot.fd
}

build_shim() {
    pushd shim
    git submodule update --init

    # enable verbose
    sed -i 's,UINT32 verbose = 0,UINT32 verbose = 1,' globals.c 

    # comment out sbat checking in pe.c(grub in Ubuntu 18 doesn't support sbat)
    sed -i '/efi_status = handle_sba/a efi_status = EFI_SUCCESS;' pe.c
    make clean
    make VENDOR_CERT_FILE=../xiaoxin-ca.cer ENABLE_SHIM_CERT=1

    $OSSLSIGNCODE sign -in shimx64.efi -certs ../certs/Uefi.crt -key ../certs/Uefi.key -out shimx64.efi.signed
    #XXX $OSSLSIGNCODE sign -in /home/admin/test/main.efi -certs ../certs/Uefi.crt -key ../certs/Uefi.key -out shimx64.efi.signed

    popd
}

build_grub() {
    rm -rf EFI
    mkdir EFI

    # with --pukey to enable check_signature in grub
    GRUB_MKIMAGE="$GRUB_MKIMAGE --pubkey=./test_user_id.key"
    # for hard drive
    $GRUB_MKIMAGE \
        --compression=xz \
        --directory $GRUB_DIR \
        --output EFI/grubx64.efi \
        --prefix /EFI/BOOT \
        --format x86_64-efi \
        $GRUB_MODULES

    # for iso
cat  <<EOF >> ./grub-early.cfg
configfile (\$root)/grub.cfg
EOF

    $GRUB_MKIMAGE \
        -c ./grub-early.cfg \
        --compression=xz \
        --directory $GRUB_DIR \
        --output EFI/iso-grubx64.efi \
        --prefix /EFI/BOOT \
        --format x86_64-efi \
        $GRUB_MODULES_ISO

    # sign 
    pesign --force -s -n ./ca/uefi_sb_signer -c "Xiaoxin UEFI SB Signer" -i EFI/grubx64.efi -o EFI/grubx64.efi.signed
    pesign --force -s -n ./ca/uefi_sb_signer -c "Xiaoxin UEFI SB Signer" -i EFI/iso-grubx64.efi -o EFI/iso-grubx64.efi.signed
}

cat /etc/os-release | grep -q '"Ubuntu"'

if [ $? -eq 0 ] ; then
	# Ubuntu
	KVM=/usr/bin/kvm
	ISOLINUX_BIN=/usr/lib/ISOLINUX/isolinux.bin
	LDLINUX_C32=/usr/lib/syslinux/modules/bios/ldlinux.c32
	GRUB_MKIMAGE=/usr/bin/grub-mkimage
    	GRUB_MODULES_ISO="iso9660 normal boot linux multiboot true configfile loopback chain efifwsetup efi_gop efi_uga ls cat echo ls memdisk udf linuxefi"
    	GRUB_MODULES="fat iso9660 part_gpt part_msdos normal boot linux configfile loopback chain efifwsetup efi_gop efi_uga ls search search_label search_fs_uuid search_fs_file test all_video loadenv exfat ext2 udf linuxefi pgp gcry_sha256 gcry_sha512 gcry_dsa gcry_rsa"
	EFIKEYGEN="efikeygen"
	ISOHDPFX_BIN=/usr/lib/ISOLINUX/isohdpfx.bin
else
	# CentOS
	KVM=/usr/libexec/qemu-kvm
	ISOLINUX_BIN=/usr/share/syslinux/isolinux.bin
	LDLINUX_C32=/usr/share/syslinux/ldlinux.c32
	GRUB_MKIMAGE=/usr/bin/grub2-mkimage
    	GRUB_MODULES_ISO="iso9660 normal boot linux multiboot true configfile loopback chain efifwsetup efi_gop efi_uga ls cat echo ls memdisk udf linux"
    	GRUB_MODULES="fat iso9660 part_gpt part_msdos normal boot linux configfile loopback chain efifwsetup efi_gop efi_uga ls search search_label search_fs_uuid search_fs_file test all_video loadenv exfat ext2 udf linux pgp gcry_sha256 gcry_sha512 gcry_dsa gcry_rsa"
	EFIKEYGEN="efikeygen --kernel"
	ISOHDPFX_BIN=/usr/share/syslinux/isohdpfx.bin
fi

GRUB_MODDEP_LST=/usr/lib/grub/x86_64-efi/moddep.lst
GRUB_MODDEP_LST=/usr/local/my-grub/lib/grub/x86_64-efi/moddep.lst
GRUB_MKIMAGE=/usr/local/my-grub/bin/grub-mkimage
GRUB_DIR=/usr/local/my-grub/lib/grub/x86_64-efi/
PESIGN=/usr/bin/pesign
MAKE=/usr/bin/make
GCC=/usr/bin/gcc
GPP=/usr/bin/g++
NASM=/usr/bin/nasm
GENISOIMAGE=/usr/bin/genisoimage
UUID_H=/usr/include/uuid/uuid.h
IASL=/usr/bin/iasl
XORRISO=/usr/bin/xorriso
PYTHON3=/usr/bin/python3
OSSLSIGNCODE=/usr/bin/osslsigncode
MKDOSFS=/sbin/mkdosfs

for f in "$ISOLINUX_BIN" "$LDLINUX_C32" "$GRUB_MKIMAGE" "$GRUB_MODDEP_LST" "$PESIGN" "$MAKE" "$GCC" "$GPP" "$NASM" "$GENISOIMAGE" "$UUID_H" "$IASL" "$XORRISO" "$KVM" "$PYTHON3" "$OSSLSIGNCODE" "$MKDOSFS" ; do
	if [ ! -f "$f" ] ; then
		echo "Missing $f" && exit 1
	fi
done

git submodule update --init

IDX=1006

# Step 1 - gpg
#create_gpg_key

# Step 2 - Create certificates
#create_certificates

# Step 3- Build EDK
# build_edk

# Step 4 - Create Secure boot signer ca
# create_singer_ca

# Step 5 - Build shim
# build_shim

# Step 6 - Build grubx64
build_grub

# create install iso
WORK_DIR="./work"
ISOLINUX_DIR="$WORK_DIR/isolinux"
EFI_IMG="$WORK_DIR/efi.img"

mkdir -p $ISOLINUX_DIR

cp $ISOLINUX_BIN $ISOLINUX_DIR
cp $LDLINUX_C32 $ISOLINUX_DIR

cat  << EOF > $ISOLINUX_DIR/isolinux.cfg
SAY Linux Installer
TIMEOUT 30
SERIAL 0 9600
DEFAULT linux-install
LABEL linux-install
 KERNEL /vmlinuz console=ttyS0,115200 console=tty1
 APPEND initrd=/initrd.img,/smi.img
EOF

dd if=/dev/zero of=${EFI_IMG} bs=2048 count=2048
#dd if=/dev/zero of=${EFI_IMG} bs=1024 count=2048
mkfs.vfat ${EFI_IMG}
mmd -i ${EFI_IMG} efi
mmd -i ${EFI_IMG} efi/boot

pesign --force -s -n ./ca/uefi_sb_signer -c "Xiaoxin UEFI SB Signer" -i smi/vmlinuz.unsigned  -o $WORK_DIR/vmlinuz
cp $WORK_DIR/vmlinuz smi/base.part/vmlinuz

rm $WORK_DIR/vmlinuz.sig
rm smi/base.part/initrd.img.sig

gpg --homedir ./gnupg --detach-sign $WORK_DIR/vmlinuz 
gpg --homedir ./gnupg --detach-sign smi/base.part/initrd.img

cp $WORK_DIR/vmlinuz.sig smi/base.part/vmlinuz.sig

mkdir -p $WORK_DIR/smi
#XXX ( cd ./smi/base.part && tar -p --owner=root --group=root -cf - --use-compress-program=xz .) > $WORK_DIR/smi/base.part.tar.xz
( cd ./smi/base.part && tar -p --owner=root --group=root -cf - .) > $WORK_DIR/smi/base.part.tar.xz

mcopy -i ${EFI_IMG} EFI/iso-grubx64.efi.signed ::efi/boot/grubx64.efi
mcopy -i ${EFI_IMG} shim/shimx64.efi.signed ::efi/boot/bootx64.efi

EFI_PART="./smi/smi.img/smi/partition/efi.part"
dd if=/dev/zero of=$EFI_PART bs=1024 count=131072
mkfs.vfat -n "UEFI       " ${EFI_PART}
mmd -i ${EFI_PART} efi
mmd -i ${EFI_PART} efi/boot
mcopy -i ${EFI_PART} EFI/grubx64.efi.signed ::efi/boot/grubx64.efi
mcopy -i ${EFI_PART} shim/shimx64.efi.signed ::efi/boot/bootx64.efi

cat  <<EOF > ${EFI_PART}.grub.cfg
set debug=all
export debug

search --label cloudimg-rootfs --set prefix
configfile (\$prefix)/boot/grub/grub.cfg
EOF

mcopy -i ${EFI_PART} ${EFI_PART}.grub.cfg ::efi/boot/grub.cfg
tar -p --owner=root --group=root -cf - --use-compress-program=xz ${EFI_PART}  > ${EFI_PART}.tar.xz

( cd ./smi/smi.img && find . -print0 | cpio --null  --create --verbose --format=newc | gzip --best) > $WORK_DIR/smi.img

cat  <<EOF > ${WORK_DIR}/grub.cfg
echo SMI Disk Installer
set debug=all

linux /vmlinuz console=ttyS0,115200 console=tty1
initrd /initrd.img /smi.img
boot
EOF

cp smi/initrd.img $WORK_DIR/initrd.img

#xorriso -as genisoimage -b isolinux/isolinux.bin -c isolinux/boot.cat -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -no-emul-boot -e efi.img -isohybrid-gpt-basdat  -V smi-install-iso -joliet -joliet-long -input-charset 'utf-8' -rock -output b2.iso $WORK_DIR

xorriso -as genisoimage -b isolinux/isolinux.bin -c isolinux/boot.cat -isohybrid-mbr $ISOHDPFX_BIN -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -no-emul-boot -e efi.img -isohybrid-gpt-basdat  -V smi-install-iso -joliet -joliet-long -input-charset 'utf-8' -rock -output b2.iso $WORK_DIR
