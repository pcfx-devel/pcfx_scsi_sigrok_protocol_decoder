##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2024 David Shadoff <david.shadoff@gmail.com>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
from collections import deque

class SamplerateError(Exception):
    pass


def getluns(datapins):
    value = "LUN "
    first = 0
    for iter in range (7, 0, -1):
        if datapins[iter] == 0:
            if first == 0:
                value = value + str(iter)
                first = 1
            else:
                value = value + "," + str(iter)
    return value


def getbyteval(datapins):
    number = 0
    for iter in range (0, 7):
        if datapins[iter] == 0:
            number = number + (1 << iter)
    value = '0x%2.2X' % number
    return value


def subphase_label(subphase):
    if subphase == 0:
        sp_label = ['Message In',      'Msg In',   'MI']
    elif subphase == 1:
        sp_label = ['Message Out',     'Msg Out',  'MO']
    elif subphase == 2:
        sp_label = ['Unused Subphase', 'Unused',   'U']
    elif subphase == 3:
        sp_label = ['Unused Subphase', 'Unused',   'U']
    elif subphase == 4:
        sp_label = ['Status',          'Stat',     'S']
    elif subphase == 5:
        sp_label = ['Command',         'Cmd',      'C']
    elif subphase == 6:
        sp_label = ['Data In',         'Data In',  'DI']
    else:
        sp_label = ['Data Out',        'Data Out', 'DO']
    return sp_label


class Decoder(srd.Decoder):
    api_version = 3
    id = 'pcfx_scsi'
    name = 'PCFX SCSI'
    longname = 'PCFX SCSI'
    desc = 'SCSI protocol for NEC PC-FX videogame console'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = []
    tags = ['Retro computing']
    channels = (
        {'id': 'scsi_d0',  'name': 'D0',  'desc': 'Data 0'},
        {'id': 'scsi_d1',  'name': 'D1',  'desc': 'Data 1'},
        {'id': 'scsi_d2',  'name': 'D2',  'desc': 'Data 2'},
        {'id': 'scsi_d3',  'name': 'D3',  'desc': 'Data 3'},
        {'id': 'scsi_d4',  'name': 'D4',  'desc': 'Data 4'},
        {'id': 'scsi_d5',  'name': 'D5',  'desc': 'Data 5'},
        {'id': 'scsi_d6',  'name': 'D6',  'desc': 'Data 6'},
        {'id': 'scsi_d7',  'name': 'D7',  'desc': 'Data 7'},
        {'id': 'scsi_sel', 'name': 'SEL', 'desc': 'Sel'},
        {'id': 'scsi_bsy', 'name': 'BSY', 'desc': 'Busy'},
        {'id': 'scsi_cd',  'name': 'CD',  'desc': 'Cmd'},
        {'id': 'scsi_io',  'name': 'IO',  'desc': 'I/O'},
        {'id': 'scsi_msg', 'name': 'MSG', 'desc': 'Msg'},
        {'id': 'scsi_req', 'name': 'REQ', 'desc': 'Req'},
        {'id': 'scsi_ack', 'name': 'ACK', 'desc': 'Ack'},
    )

# Each of these defines a piece of data and a color
#
# You can several of these on the same row, or they can be separated
# onto different rows below
#
    annotations = (
        ('5',  'bus_free',    'Bus Free'),           # 0 = (row 1)
        ('6',  'arbitration', 'Arbitration'),        # 1 = (row 1)
        ('7',  'selection',   'Selection'),          # 2 = (row 1)
        ('8',  'reselection', 'Reselection'),        # 3 = (row 1)
        ('9',  'inf_xfer',    'Info Xfer'),          # 4 = (row 1)
        ('11', 'unused',      'Unused'),             # 5 = (row 1)
        ('12', 'unused',      'Unused'),             # 6 = (row 1)
        ('10', 'unused',      'Unused'),             # 7 = (row 1)
        ('1',  'unused',      'Unused'),             # 8 = (row 1)
        ('4',  'unused',      'Unused'),             # 9 = (row 1)
        ('0',  'reset',       'Reset'),              # 10 = (row 1)

        ('3',  'unit',        'Unit'),               # 11 = (row 2)
        ('6',  'msg_in',      'Message In'),         # 12 = (row 2)
        ('6',  'msg_out',     'Message Out'),        # 13 = (row 2)
        ('0',  'unused',      'Unused'),             # 14 = (row 2)
        ('0',  'unused',      'Unused'),             # 15 = (row 2)
        ('9',  'status',      'Status'),             # 16 = (row 2)
        ('4',  'command',     'Command'),            # 17 = (row 2)
        ('13', 'data_in',     'Data In'),            # 18 = (row 2)
        ('1',  'data_out',    'Data Out'),           # 19 = (row 2)

        ('6',  'datatotgt',   'Data to Target'),     # 20 = (row 3)
        ('6',  'datafromtgt', 'Data from Target'),   # 21 = (row 4)
    )
    annotation_rows = (
        ('phase',         'Phase',       (0,1,2,3,4,5,6,7,8,9,10,)),
        ('type',          'Type',        (11,12,13,14,15,16,17,18,19,)),
        ('to_target',     'To Target',   (20,)),
        ('from_target',   'From Target', (21,)),
    )

# Note - SCSI Phases:
#   Bus Free
#   Arbitration
#   Selection
#   Reselection
#   Command     --|
#   Data In       |
#   Data Out      |- These are often grouped and categorized as "Information Transfer"
#   Status        |
#   Message In    |
#   Message Out --|


    def __init__(self, **kwargs):
        self.reset()

    def reset(self):
        self.samplerate = None
        self.last_samplenum = None
        self.state = 'BUS FREE'      # starting state for state machine
        self.startsamplenum = 0      # detect start sample of overall phase
        self.phasestartsample = 0    # detect start sample of suphasephase
        self.datastartsample = 0     # detect start sample of data 
        self.datafound = 0           # Do not display subphases unless data was actually transferred within them
                                     # (could just be CD/IO/MSG toggling)
        self.busyhigh_samplenum = 0  # for glitch filter



    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)


    #
    # NOTE - Not yet implemented:
    # ---------------------------
    #
    # 1) Note that any time SCSI RESET goes low (all phases but BUS FREE):
    #    a) the command is aborted
    #    b) devices are disconnected, and
    #    c) phase goes to BUS FREE
    # (need to add SCSI_RST as input)
    #
    # 2) Currently, SCSI_ATN is not evaluated
    #
    # 3) No time values are currently evaluated (i.e. settling time or timeouts)
    #
    def decode(self):
        if not self.samplerate:
            raise SamplerateError('Cannot decode without samplerate.')

        while True:
            if self.state == 'BUS FREE':
                # Wait for falling transition on channel 8 (scsi_sel), which starts arbitration/selection
                self.wait({8: 'f'})
                self.put(self.startsamplenum, self.samplenum, self.out_ann,
                                 [0, ['Bus Free', 'Free', 'F']])
                self.state = 'ARBITRATION'
                self.startsamplenum = self.samplenum


            if self.state == 'ARBITRATION':
                # Wait for falling transition on channel 9 (scsi_bsy), which completes arbitration
                (d0, d1, d2, d3, d4, d5, d6, d7, scsi_sel, scsi_bsy, scsi_cd, scsi_io, scsi_msg, scsi_req, scsi_ack) = self.wait({9: 'f'})
                pins = (d0, d1, d2, d3, d4, d5, d6, d7, scsi_sel, scsi_bsy, scsi_cd, scsi_io, scsi_msg, scsi_req, scsi_ack)
                value = getluns(pins)
                self.put(self.startsamplenum, self.samplenum, self.out_ann,
                                 [1, ['Arbitration', 'Arb', 'A']])
                self.put(self.startsamplenum, self.samplenum, self.out_ann,
                                 [11, [value]])
                self.state = 'SELECT'
                self.startsamplenum = self.samplenum

            if self.state == 'SELECT':
                # Wait for rising transition on channel 8 (scsi_sel), which completed selection
                (d0, d1, d2, d3, d4, d5, d6, d7, scsi_sel, scsi_bsy, scsi_cd, scsi_io, scsi_msg, scsi_req, scsi_ack) = self.wait({8: 'r'})
                value = getluns(pins)
                self.put(self.startsamplenum, self.samplenum, self.out_ann,
                                 [2, ['Selection', 'Sel', 'Se']])
                self.put(self.startsamplenum, self.samplenum, self.out_ann,
                                 [11, [value]])
                self.state = 'INFO XFER'
                self.startsamplenum = self.samplenum
                # set up for (potential) data captures
                self.datafound = 0
                self.datastartsample = self.samplenum
                # get values of cd, io, msg for subphase
                self.subphase = (scsi_msg << 2) + (scsi_cd << 1) + scsi_io
                self.phasestartsample = self.samplenum
                self.busyhigh_samplenum = self.samplenum  # for glitch filter


            if self.state == 'INFO XFER':
                # Within Command, two signals are most important: SCSI_CD and SCSI_IO
                # SCSI_CD = Command (when low), Data (when High)
                # SCSI_IO = Input (when low), Output (when High)
                #
                # Wait for rising transition on channel 9 (scsi_bsy), which completes transaction
                (d0, d1, d2, d3, d4, d5, d6, d7, scsi_sel, scsi_bsy, scsi_cd, scsi_io, scsi_msg, scsi_req, scsi_ack) = self.wait([{10: 'e'}, {11: 'e'}, {12: 'e'}, {14: 'f'}, {14: 'r'}, {9: 'h'}])
                pins = (d0, d1, d2, d3, d4, d5, d6, d7, scsi_sel, scsi_bsy, scsi_cd, scsi_io, scsi_msg, scsi_req, scsi_ack)

                if ((self.matched & (0b1 << 0)) or (self.matched & (0b1 << 1)) or (self.matched & (0b1 << 2))):
                    temp_subphase = (scsi_msg << 2) + (scsi_cd << 1) + scsi_io
                    if self.datafound > 0:
                        subph_label = subphase_label(self.subphase)
                        self.put(self.phasestartsample, self.samplenum, self.out_ann,
                                     [(12+self.subphase), subph_label])
                    self.phasestartsample = self.samplenum
                    self.subphase = temp_subphase
                    self.datafound = 0
                    self.datastartsample = self.samplenum

                # falling ACK (end of REQ, start of ACK) means data should be sampled
                if (self.matched & (0b1 << 3)):
                    self.dataval = getbyteval(pins)

                # rising ACK means end of data pulse
                if (self.matched & (0b1 << 4)):
                    if (self.subphase & (0b1 << 0)):
                        self.put(self.datastartsample, self.samplenum, self.out_ann,
                                         [20, [self.dataval]])
                    else:
                        self.put(self.datastartsample, self.samplenum, self.out_ann,
                                         [21, [self.dataval]])
                    self.datafound = self.datafound + 1
                    self.datastartsample = self.samplenum

                # High BSY means end of Information Transfer phase
                if (self.matched & (0b1 << 5)):
                    if ((self.samplenum - self.busyhigh_samplenum) < 2):      # glitch filter
                        self.put(self.startsamplenum, self.samplenum, self.out_ann,
                                         [4, ['Information Transfer', 'Info Xfer', 'Inf']])
                        self.state = 'BUS FREE'
                        self.startsamplenum = self.samplenum
                    else:
                        self.busyhigh_samplenum = self.samplenum


            self.last_samplenum = self.samplenum
