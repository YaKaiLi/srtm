cmd_/root/srtm/driverIoctl/helloworld_export/export_test.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -T ./scripts/module-common.lds  --build-id  -o /root/srtm/driverIoctl/helloworld_export/export_test.ko /root/srtm/driverIoctl/helloworld_export/export_test.o /root/srtm/driverIoctl/helloworld_export/export_test.mod.o ;  true
