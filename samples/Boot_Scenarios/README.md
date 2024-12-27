# pcfx_scsi_sigrok_protocol_decoder - Boot Specific Samples
Boot specific samples for PC-FX SCSI

## Introduction

During bootup, the PC-FX displays a "splash screen" for a period of approximately 10 seconds;
during this time, it initializes the SCSI bus and probes what kind of media is there.

The SCSI probe takes place at roughly the 5-second mark, and recognizes the media type (if any) within about 1 second.

The initial probe generally consists of:
 - 0x00 Test Unit Ready
 - 0x03 Request Sense

If there is no media on the drive (but it is closed), this will be retried approximately 75 times.

If the lid is open, there is no retry.

If there is media, there will be an attempt to read the table of contents for all tracks, in order to infer
whether there is audio and whether there is data.

If Data exists, it will read the type (i.e. MODE1/2048 or MODE2/2352), and read a sector to identify whether
the disc is PhotoCD, or PC-FX, or unknown.


At the end of the 10-second mark, one of two things happens:
 1. If there is boot media in the FX-BMP slot, it will copy that program to memory and execute it without
showing the boot menu.

 2. Otherwise, it will display the boot menu.  It may display an error message if it can't determien media
type, but will otherwise position the cursor over the most appropriate choice for execution - CD, PhotoCd,
or PC-FX game.  If no action is taken within a few seconds, it will act as though you agree with that choice,
and run the appropriate program.

