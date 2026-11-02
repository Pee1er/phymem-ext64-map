Title: Shenzhen Moyea Software phymem_ext64.sys physical memory map

Vendor: Shenzhen Moyea Software
Product: PhyMem
Component: phymem_ext64.sys
SHA-256: e26a21e1b79ecaee7033e05edb0bd72aca463c23bd6fdf5835916ce2dfdf1a63
MD5: a125390293d50091b643cfa096c2148c
SHA-1: ff9887cfd695916a06319b3a96f7ab2e6343a20e
Size: 15248 bytes
PE timestamp: 2014-08-20 03:33:26 UTC
FileVersion: not present
ProductVersion: not present
OriginalFilename: not present
Authenticode status: Valid
Signer: CN=Shenzhen Moyea Software, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Shenzhen Moyea Software, L=ShenZhen, S=GuangDong, C=CN
Certificate thumbprint: A1A5ADDBE1025FEDF615C8F58E4062B9E1D7B792
Certificate not before: 2013-06-26 00:00:00 UTC
Certificate not after: 2015-07-26 23:59:59 UTC
Device: \\.\PhyMem2
PDB: e:\new_panda\register_new\driver\objfre_win7_amd64\amd64\phymem.pdb

CVE:

Description:
phymem_ext64.sys in Shenzhen Moyea Software PhyMem (SHA-256 e26a21e1b79ecaee7033e05edb0bd72aca463c23bd6fdf5835916ce2dfdf1a63, 15248 bytes, PE timestamp 2014-08-20 03:33:26 UTC) passes a caller-supplied 64-bit physical address and a caller-supplied length to MmMapIoSpace on IOCTL 0x80002000 (METHOD_BUFFERED), keeps the high 32 bits of that address, does not translate a bus address, maps the range as non-cached, does not validate the address range, and returns a writable user-mode mapping to the calling process, which allows a local user to read and write arbitrary physical memory and locally escalate privileges via \\.\PhyMem2. This file has no VERSIONINFO. The Authenticode status is Valid, signed by CN=Shenzhen Moyea Software, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Shenzhen Moyea Software, L=ShenZhen, S=GuangDong, C=CN, thumbprint A1A5ADDBE1025FEDF615C8F58E4062B9E1D7B792. On 2026-11-03, on an isolated Windows 10 Enterprise LTSC 2021 virtual machine (10.0.19044.7807), an administrator loaded this file and the service started. The administrator locked one of its own pages at physical address 0x134b7b000 and did not send the IOCTL. Local account aida-low, a member of Users and not a member of Administrators, opened \\.\PhyMem2 and sent IOCTL 0x80002000 for that address with length 0x10. Through the user-mode mapping returned to that process, that account wrote 0x5A and read 0x5A back, then wrote 0xA5 and read 0xA5 back. The administrator read the first byte of that physical page and saw 0x5A, then 0xA5. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on IOCTL 0x80002000, map only a physical address chosen inside the driver, and limit access to \\.\PhyMem2 to Administrators and SYSTEM.
