# pcfx_scsi_sigrok_protocol_decoder
Protocol decoder for sigrok/pulseview-based logic state analyzers for decoding SCSI data

## Introduction

The PC-FX uses SCSI to communicate to the internal CDROM (and potentially other devices).
This data can be seen travelling between the PC-FX main board and the CDROM daughterboard,
along with a few additional signals.

## The Protocol Decoder

### How To Install

On DSView, there is a folder called 'decoders' within the application folder for DSView; within this
folder are subfolders for each protocol decoder. Copy the 'pcfx-scsi' folder here into its corresponding
location in the application subfolder.  (For PulseView or other sigrok-compatible software, consult the
application's instructions).

### How To Use

Once you have installed the protocol decoder, it should be selectable in the list of protocol decoders.

The protocol decoder adds several annotation rows, to be able to interpret the bitstream in several
different ways; each of them can be displayed or suppressed.  These rows include:
 - bit values (electrical or internal representation, as internal is the inverse of electrical)
 - byte values (4 x 8-bit bytes per scan)
 - word values (evaluated as a 32-bit word)
 - controller values (based on controller type, what buttons (or values) are represented ?

An example is shown below (from an actual data capture):

![Multitap](img/PCFX_SCSI.JPG)

### What exactly is this 'sigrok' thing ?

The sigrok project aims at creating a portable, cross-platform, Free/Libre/Open-Source signal analysis software suite that supports
various device types (e.g. logic analyzers, oscilloscopes, and many more).
(taken from [the project's home page](https://sigrok.org/wiki/Main_Page) )

The specification for protocol analyzers (for logic state analysis) is extensible and there are many
example protocols available.


### Why write a decoder ?

I had already done signal captures and understood the meanings of some state transitions of the signals for PC-FX SCSI,
but I needed to understand more about the SCSI standard, and how it was implemented on the PC-FX.

However, it was quite tedious trying to interpret the bit values and see "the bigger picture", and I wished I had a
protocol decoder like this one to help interpret.



## NOTES:

While this protocol decoder has been written according to sigrok standards, I have (so far) only
installed and tested on "DSView", used in conjunction with my DreamSource Labs' DSLogic U3Pro32
logic state analyzer, and not PulseView.  HOWEVER, I do intend to obtain a low-cost analyzer and
test with PulseView at some point in the near future.  (I have no reason to believe that it won't
work on the first attempt).

I have not yet submitted this into the sigrok project, as there are still a few framing error
conditions I'd like to identify and display, and I want to do testing on the actual PulseView
software first.

I also may wish to do a little more code cleanup before submission.  I'm not familiar with their
review process, so I have no idea how long it will take to be approved (or receive feedback).

