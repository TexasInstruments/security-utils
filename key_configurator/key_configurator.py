# Copyright (C) 2025 Texas Instruments Incorporated
#
# All rights reserved not granted herein.
# Limited License.  
#
# Texas Instruments Incorporated grants a world-wide, royalty-free, 
# non-exclusive license under copyrights and patents it now or hereafter 
# owns or controls to make, have made, use, import, offer to sell and sell ("Utilize")
# this software subject to the terms herein.  With respect to the foregoing patent 
# license, such license is granted  solely to the extent that any such patent is necessary 
# to Utilize the software alone.  The patent license shall not apply to any combinations which 
# include this software, other than combinations with devices manufactured by or for TI (TI Devices).
# No hardware patent is licensed hereunder.
#
# Redistributions must preserve existing copyright notices and reproduce this license (including the 
# above copyright notice and the disclaimer and (if applicable) source code license limitations below) 
# in the documentation and/or other materials provided with the distribution
#
# Redistribution and use in binary form, without modification, are permitted provided that the following
# conditions are met:
#
#	* No reverse engineering, decompilation, or disassembly of this software is permitted with respect to any 
#     software provided in binary form.
#	* any redistribution and use are licensed by TI for use only with TI Devices.
#	* Nothing shall obligate TI to provide you with source code for the software licensed and provided to you in object code.
#
# If software source code is provided to you, modification and redistribution of the source code are permitted 
# provided that the following conditions are met:
#
#   * any redistribution and use of the source code, including any resulting derivative works, are licensed by 
#     TI for use only with TI Devices.
#   * any redistribution and use of any object code compiled from the source code and any resulting derivative 
#     works, are licensed by TI for use only with TI Devices.
#
# Neither the name of Texas Instruments Incorporated nor the names of its suppliers may be used to endorse or 
# promote products derived from this software without specific prior written permission.
#
# DISCLAIMER.
#
# THIS SOFTWARE IS PROVIDED BY TI AND TI'S LICENSORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
# IN NO EVENT SHALL TI AND TI'S LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

import json
import time
import threading
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import hashlib

KEYWR_LITE_CMD_TO_CMD_ID_MAP = {
    "one-shot" : 0,
    "multi-shot" : 1,
    "smpkh" : 2,
    "bmpkh" : 3,
    "key-cnt" : 4,
    "key-rev" : 5,
    "sbl-swrev" : 6,
    "sysfw-swrev" : 7,
    "brdcfg-swrev" : 8,
    "msv" : 9,
    "jtag-disable" : 10,
    "boot-mode": 11,
    "ext-otp" : 12
}

with open("tool_data.json") as fl:
    tool_data = json.loads(fl.read())
    tool_version = str(tool_data["tool-version"]["version"])
    tool_subversion = str(tool_data["tool-version"]["subversion"])
    tool_patchversion = str(tool_data["tool-version"]["patchversion"])
    disclaimer = tool_data["disclaimer"]
    soc_data = tool_data["devices"]

KEYWRITER_DEVICES = list(soc_data.keys())

def str_is_int(str):
    """
    Check if a string represents an integer.
    """
    int_digits=set("0123456789")
    return all(c in int_digits for c in str)

def str_is_hex(str):
    """
    Check if a string represents a hex string.
    """
    hex_digits=set("0123456789abcdefABCDEF")
    return all(c in hex_digits for c in str)

def ext_otp_get_octet_and_bit_idx(row_idx):
    """
    """
    ret_octet_idx = 7 - int(row_idx/8)
    ret_bit_idx = (row_idx%8)
    return (ret_octet_idx, ret_bit_idx)

def ext_otp_get_row_idx(octet_idx, bit_idx):
    """
    """
    row_idx = (7 - octet_idx)*8
    row_idx += bit_idx

def hash_file(file_path):
    """
    Function to calculate sha512 hash of a binary file.
    """
    hash_func = hashlib.new("sha512")
    with open(file_path, 'rb') as fl:
        for block in iter(lambda: fl.read(65536), b''):
            hash_func.update(block)
    return hash_func.hexdigest()

def hash_blob(blob):
    """
    Function to calculate sha512 of binary blob.
    """
    hash_func = hashlib.new("sha512")
    hash_func.update(blob)
    return hash_func.hexdigest()

def calculate_hash_from_file(entry_widget):

    file_path = filedialog.askopenfilename(
        title="Select Public Key File",
        filetypes=[("Public Key Files", ".der")]
    )
    if not file_path:
        return  # User canceled file selection
    
    try:    
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, hash_file(file_path))
    except:
        pass

class keywrlite_type_uint8_t:
    def __init__(self, val=0):
        """
        Class initialisation function.
        """
        if isinstance(val, int):
            self.VAL = val
        else:
            self.VAL = int(val, 16)
    def tobin(self):
        return (((self.VAL) & 0xff).to_bytes(1, 'little'))
    
    def toStr(self):
        return str(self.VAL)
    
    def toHexStr(self):
        return hex(self.VAL)
    
    def toHexArrStr(self):
        return self.toHexStr()
    
class keywrlite_type_uint16_t:
    def __init__(self, val=0):
        """
        Class initialisation function.
        """
        if isinstance(val, int):
            self.VAL = val
        else:
            self.VAL = int(val, 16)
    def tobin(self):
        return (((self.VAL) & 0xffff).to_bytes(2, 'little'))
    
    def toStr(self):
        return str(self.VAL)
    
    def toHexStr(self):
        return hex(self.VAL)
    
    def toHexArrStr(self):
        retStr = ""
        retStr += hex(((self.VAL) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 8) & 0xff))
        return retStr
    
class keywrlite_type_uint32_t:
    def __init__(self, val=0):
        """
        Class initialisation function.
        """
        if isinstance(val, int):
            self.VAL = val
        else:
            self.VAL = int(val, 16)
    def tobin(self):
        return (((self.VAL) & 0xffffffff).to_bytes(4, 'little'))
    
    def toStr(self):
        return str(self.VAL)
    
    def toHexStr(self):
        return hex(self.VAL)
    
    def toHexArrStr(self):
        retStr = ""
        retStr += hex(((self.VAL) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 8) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 16) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 24) & 0xff))
        return retStr
    
class keywrlite_type_uint64_t:
    def __init__(self, val=0):
        """
        Class initialisation function.
        """
        if isinstance(val, int):
            self.VAL = val
        else:
            self.VAL = int(val, 16)
    def tobin(self):
        return (((self.VAL) & 0xffffffffffffffff).to_bytes(8, 'little'))

    def toStr(self):
        return str(self.VAL)
    
    def toHexStr(self):
        return hex(self.VAL)

    def toHexArrStr(self):
        retStr = ""
        retStr += hex(((self.VAL) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 8) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 16) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 24) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 32) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 40) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 48) & 0xff)) + ", "
        retStr += hex(((self.VAL >> 56) & 0xff))
        return retStr

class keywrlite_type_array:
    def __init__(self):
        """
        Class initialisation function.
        """
        self.ARR = []
    def empty(self):
        self.ARR = []
    def add(self, item):
        self.ARR.append(item)
    def tobin(self):
        retbin = b''
        for item in self.ARR:
            retbin += item.tobin()
        return retbin

    def toHexStr(self):
        retstr = ""
        lt = len(self.ARR)
        for i in range(0, len(self.ARR)):
            retstr += self.ARR[i].toHexStr()
            if i < lt-1:
                retstr += ", "
        return retstr

    def toHexArrStr(self):
        retstr = ""
        lt = len(self.ARR)
        for i in range(0, len(self.ARR)):
            retstr += self.ARR[i].toHexArrStr()
            if i < lt-1:
                retstr += ", "
        return retstr

class keywrlite_action_flags(keywrlite_type_uint32_t):
    """
    <wp> <rp> <override> <active/inactive>
    """
    def __init__(self, act=False, rp=False, wp=False, ovrd=False):
        """
        Class initialisation function.
        """
        FLAG = 0
        if act:
            FLAG |= 0x5a
        else:
            FLAG |= (0xa5)
        if ovrd:
            FLAG |= (0x5a << 8)
        else:
            FLAG |= (0xa5 << 8)
        if rp:
            FLAG |= (0x5a << 16)
        else:
            FLAG |= (0xa5 << 16)
        if wp:
            FLAG |= (0x5a << 24)
        else:
            FLAG |= (0xa5 << 24)
        super().__init__(FLAG)
    def enable(self, flag):
        self.VAL &= 0xffffff00
        if flag:
            self.VAL |= (0x5a)
        else:
            self.VAL |= (0xa5)
    def override(self, flag):
        self.VAL &= 0xffff00ff
        if flag:
            self.VAL |= (0x5a << 8)
        else:
            self.VAL |= (0xa5 << 8)
    def read_protect(self, flag):
        self.VAL &= 0xff00ffff
        if flag:
            self.VAL |= (0x5a << 16)
        else:
            self.VAL |= (0xa5 << 16)
    def write_protect(self, flag):
        self.VAL &= 0x00ffffff
        if flag:
            self.VAL |= (0x5a << 24)
        else:
            self.VAL |= (0xa5 << 24)

class keywrlite_header:
    """
    struct keywriter_lite_header {
        uint16_t magic;
        uint16_t size;
        uint8_t abi_major;
        uint8_t abi_minor;
        uint16_t reserved0;
        uint32_t cmd_id;
        uint32_t reserved1[2];
    } __attribute__((packed));
    """

    def __init__(self, magic=0x9012, size=0, abi_maj=0, abi_min=1, cmd_id=0):
        """
        Class initialisation function.
        """
        self.magic = keywrlite_type_uint16_t(magic)
        self.size = keywrlite_type_uint16_t(size)
        self.abi_major = keywrlite_type_uint8_t(abi_maj)
        self.abi_minor = keywrlite_type_uint8_t(abi_min)
        self.reserved0 = keywrlite_type_uint16_t()
        self.cmd_id = keywrlite_type_uint32_t(cmd_id)
        self.reserved1 = keywrlite_type_array()
        self.reserved1.add(keywrlite_type_uint32_t())
        self.reserved1.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.magic.tobin()
        retbin += self.size.tobin()
        retbin += self.abi_major.tobin()
        retbin += self.abi_minor.tobin()
        retbin += self.reserved0.tobin()
        retbin += self.cmd_id.tobin()
        retbin += self.reserved1.tobin()
        return retbin
    def getStructName(self):
        return "keywriter_lite_header"
    def getStructDeclaration(self):
        retstr = """
struct keywriter_lite_header {
    uint16_t magic;
    uint16_t size;
    uint8_t abi_major;
    uint8_t abi_minor;
    uint16_t reserved0;
    uint32_t cmd_id;
    uint32_t reserved1[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .magic = [magic],
            .size = [size],
            .abi_major = [abi_major],
            .abi_minor = [abi_minor],
            .reserved0 = [reserved0],
            .cmd_id = [cmd_id],
            .reserved1 = {[reserved1]},
        }
        """
        retstr = retstr.replace("[magic]", self.magic.toHexStr())
        retstr = retstr.replace("[size]", self.size.toStr())
        retstr = retstr.replace("[abi_major]", self.abi_major.toStr())
        retstr = retstr.replace("[abi_minor]", self.abi_minor.toStr())
        retstr = retstr.replace("[reserved0]", self.reserved0.toStr())
        retstr = retstr.replace("[cmd_id]", self.cmd_id.toStr())
        retstr = retstr.replace("[reserved1]", self.reserved1.toHexStr())
        return retstr

class  keywrlite_mpk_opts:
    """
    struct mpk_opts {
        uint32_t field_header;
        uint32_t action_flags;
        uint16_t options;
        uint16_t reserved_field;
        uint32_t reserved[2];
    } __attribute__((packed));
    """

    def __init__(self, opts=0):
        """
        Class initialisation function.
        """
        self.field_header = keywrlite_type_uint32_t(0x4a7e)
        self.action_flags = keywrlite_action_flags()
        self.options = keywrlite_type_uint16_t(opts)
        self.reserved_field = keywrlite_type_uint16_t()
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.options.tobin()
        retbin += self.reserved_field.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "mpk_opts"
    def getStructDeclaration(self):
        retstr = """
struct mpk_opts {
    uint32_t field_header;
    uint32_t action_flags;
    uint16_t options;
    uint16_t reserved_field;
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .options = [options],
            .reserved_field = [reserved_field],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[options]", self.options.toHexStr())
        retstr = retstr.replace("[reserved_field]", self.reserved_field.toHexStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_mpkh:
    """
    struct mpkh {
        uint32_t field_header;
        uint32_t action_flags;
        uint8_t mpkh[64];
        uint32_t reserved[2];
    } __attribute__((packed));
    """

    def __init__(self, smpkh=True):
        """
        Class initialisation function.
        """
        if smpkh:
            self.field_header = keywrlite_type_uint32_t(0x1234)
        else:
            self.field_header = keywrlite_type_uint32_t(0x9ffc)
        self.action_flags = keywrlite_action_flags()
        self.mpkh = keywrlite_type_array()
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.mpkh.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "mpkh"
    def getStructDeclaration(self):
        retstr = """
struct mpkh {
    uint32_t field_header;
    uint32_t action_flags;
    uint8_t mpkh[64];
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .mpkh = {[mpkh]},
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[mpkh]", self.mpkh.toHexStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_key_cnt:
    """
    struct key_cnt {
        uint32_t field_header;
        uint32_t action_flags;
        uint32_t count;
        uint32_t reserved[2];
    } __attribute__((packed));
    """

    def __init__(self, cnt=1):
        """
        Class initialisation function.
        """
        self.field_header = keywrlite_type_uint32_t(0x5678)
        self.action_flags = keywrlite_action_flags()
        self.count = keywrlite_type_uint32_t(((1 << cnt)-1))
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.count.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "key_cnt"
    def getStructDeclaration(self):
        retstr = """
struct key_cnt {
    uint32_t field_header;
    uint32_t action_flags;
    uint32_t count;
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .count = [count],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[count]", self.count.toStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_key_rev:
    """
    struct key_rev {
        uint32_t field_header;
        uint32_t action_flags;
        uint32_t revision;
        uint32_t reserved[2];
    } __attribute__((packed));
    """

    def __init__(self, rev=1):
        """
        Class initialisation function.
        """
        self.field_header = keywrlite_type_uint32_t(0x62c8)
        self.action_flags = keywrlite_action_flags()
        self.revision = keywrlite_type_uint32_t(((1 << rev)-1))
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.revision.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "key_rev"
    def getStructDeclaration(self):
        retstr = """
struct key_rev {
    uint32_t field_header;
    uint32_t action_flags;
    uint32_t revision;
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .revision = [revision],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[revision]", self.revision.toStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_sbl_swrev:
    """
    struct sbl_revision {
        uint32_t field_header;
        uint32_t action_flags;
        uint64_t swrev;
        uint32_t reserved[3];
    } __attribute__((packed));
    """

    def __init__(self, rev=1):
        """
        Class initialisation function.
        """
        self.field_header =  keywrlite_type_uint32_t(0x8bad)
        self.action_flags = keywrlite_action_flags()
        self.swrev = keywrlite_type_uint64_t(((1 << rev)-1))
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.swrev.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "sbl_revision"
    def getStructDeclaration(self):
        retstr = """
struct sbl_revision {
    uint32_t field_header;
    uint32_t action_flags;
    uint64_t swrev;
    uint32_t reserved[3];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .swrev = [swrev],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[swrev]", self.swrev.toStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_sysfw_swrev:
    """
    struct sysfw_revision {
        uint32_t field_header;
        uint32_t action_flags;
        uint64_t swrev;
        uint32_t reserved[3];
    } __attribute__((packed));
    """

    def __init__(self, rev=1):
        """
        Class initialisation function.
        """
        self.field_header =  keywrlite_type_uint32_t(0x45a9)
        self.action_flags = keywrlite_action_flags()
        self.swrev = keywrlite_type_uint64_t(((1 << rev)-1))
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.swrev.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "sysfw_revision"
    def getStructDeclaration(self):
        retstr = """
struct sysfw_revision {
    uint32_t field_header;
    uint32_t action_flags;
    uint64_t swrev;
    uint32_t reserved[3];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .swrev = [swrev],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[swrev]", self.swrev.toStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_brdcfg_swrev:
    """
    struct brdcfg_revision {
        uint32_t field_header;
        uint32_t action_flags;
        uint64_t swrev;
        uint32_t reserved[4];
    } __attribute__((packed));
    """

    def __init__(self, rev=1):
        """
        Class initialisation function.
        """
        self.field_header =  keywrlite_type_uint32_t(0x98dc)
        self.action_flags = keywrlite_action_flags()
        self.swrev = keywrlite_type_uint64_t(((1 << rev)-1))
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.swrev.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "brdcfg_revision"
    def getStructDeclaration(self):
        retstr = """
struct brdcfg_revision {
    uint32_t field_header;
    uint32_t action_flags;
    uint64_t swrev;
    uint32_t reserved[4];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .swrev = [swrev],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[swrev]", self.swrev.toStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_msv:
    """
    struct msv {
        uint32_t field_header;
        uint32_t action_flags;
        uint32_t msv;
        uint32_t reserved[2];
    } __attribute__((packed));
    """
    
    def __init__(self, msv=0):
        """
        Class initialisation function.
        """
        self.field_header =  keywrlite_type_uint32_t(0x1337)
        self.action_flags = keywrlite_action_flags()
        self.msv = keywrlite_type_uint32_t(msv)
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.msv.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "msv"
    def getStructDeclaration(self):
        retstr = """
struct msv {
    uint32_t field_header;
    uint32_t action_flags;
    uint32_t msv;
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .msv = [msv],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[msv]", self.msv.toHexStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_jtag_unlock_disable:
    """
    struct jtag_disable {
        uint32_t field_header;
        uint32_t action_flags;
        uint32_t jtag_disable;
        uint32_t reserved[2];
    } __attribute__((packed));
    """

    def __init__(self, disable=False):
        """
        Class initialisation function.
        """
        self.field_header = keywrlite_type_uint32_t(0x7421)
        self.action_flags = keywrlite_action_flags()
        if disable:
            self.jtag_disable = keywrlite_type_uint32_t(15)
        else:
            self.jtag_disable = keywrlite_type_uint32_t(0)
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.jtag_disable.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "jtag_disable"
    def getStructDeclaration(self):
        retstr = """
struct jtag_disable {
    uint32_t field_header;
    uint32_t action_flags;
    uint32_t jtag_disable;
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .jtag_disable = [jtag_disable],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[jtag_disable]", self.jtag_disable.toHexStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_boot_mode:
    """
    struct boot_mode {
        uint32_t field_header;
        uint32_t action_flags;
        uint32_t fuse_id;
        uint32_t boot_mode;
        uint32_t reserved[2];
    } __attribute__((packed));
    """

    def __init__(self, fid=1, bm=0):
        """
        Class initialisation function.
        """
        self.field_header =  keywrlite_type_uint32_t(0xa1b2)
        self.action_flags = keywrlite_action_flags()
        self.fuse_id = keywrlite_type_uint32_t(fid)
        self.boot_mode = keywrlite_type_uint32_t(int(bm, 16) & 0x1ffffff)
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.fuse_id.tobin()
        retbin += self.boot_mode.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "boot_mode"
    def getStructDeclaration(self):
        retstr = """
struct boot_mode {
    uint32_t field_header;
    uint32_t action_flags;
    uint32_t fuse_id;
    uint32_t boot_mode;
    uint32_t reserved[2];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .fuse_id = [fuse_id],
            .boot_mode = [boot_mode],
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[fuse_id]", self.fuse_id.toStr())
        retstr = retstr.replace("[boot_mode]", self.boot_mode.toHexStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_ext_otp:
    """
    struct ext_otp {
        uint32_t field_header;
        uint32_t action_flags;
        uint16_t ext_otp_size;
        uint16_t ext_otp_index;
        uint8_t ext_otp_rpwp[16];
        uint8_t ext_otp[128];
        uint32_t reserved[4];
    } __attribute__((packed));
    """

    def __init__(self):
        """
        Class initialisation function.
        """
        self.field_header =  keywrlite_type_uint32_t(0xd0e5)
        self.action_flags = keywrlite_action_flags()
        self.ext_otp_size = keywrlite_type_uint16_t()
        self.ext_otp_index = keywrlite_type_uint16_t()
        self.ext_otp_rpwp = keywrlite_type_array()
        self.ext_otp = keywrlite_type_array()
        self.reserved = keywrlite_type_array()
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
        self.reserved.add(keywrlite_type_uint32_t())
    def tobin(self):
        retbin = b''
        retbin += self.field_header.tobin()
        retbin += self.action_flags.tobin()
        retbin += self.ext_otp_size.tobin()
        retbin += self.ext_otp_index.tobin()
        retbin += self.ext_otp_rpwp.tobin()
        retbin += self.ext_otp.tobin()
        retbin += self.reserved.tobin()
        return retbin
    def getStructName(self):
        return "ext_otp"
    def getStructDeclaration(self):
        retstr = """
struct ext_otp {
    uint32_t field_header;
    uint32_t action_flags;
    uint16_t ext_otp_size;
    uint16_t ext_otp_index;
    uint8_t ext_otp_rpwp[16];
    uint8_t ext_otp[128];
    uint32_t reserved[4];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .field_header = [field_header],
            .action_flags = [action_flags],
            .ext_otp_size = [ext_otp_size],
            .ext_otp_index = [ext_otp_index],
            .ext_otp_rpwp = {[ext_otp_rpwp]},
            .ext_otp = {[ext_otp]},
            .reserved = {[reserved]},
        }
        """
        retstr = retstr.replace("[field_header]", self.field_header.toHexStr())
        retstr = retstr.replace("[action_flags]", self.action_flags.toHexStr())
        retstr = retstr.replace("[ext_otp_size]", self.ext_otp_size.toStr())
        retstr = retstr.replace("[ext_otp_index]", self.ext_otp_index.toStr())
        retstr = retstr.replace("[ext_otp_rpwp]", self.ext_otp_rpwp.toHexStr())
        retstr = retstr.replace("[ext_otp]", self.ext_otp.toHexArrStr())
        retstr = retstr.replace("[reserved]", self.reserved.toHexStr())
        return retstr

class keywrlite_checksum:
    """
    struct checksum {
        uint8_t hash[64];
    } __attribute__((packed));
    """

    def __init__(self):
        """
        Class initialisation function.
        """
        self.hash = keywrlite_type_array()
    
    def tobin(self):
        retbin = b''
        retbin += self.hash.tobin()
        return retbin
    def getStructName(self):
        return "checksum"
    def getStructDeclaration(self):
        retstr = """
struct checksum {
    uint8_t hash[64];
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .hash = {[hash]},
        }
        """
        retstr = retstr.replace("[hash]", self.hash.toHexStr())
        return retstr

class keywrlite_uboot_header:
    """
    struct uboot_header {
        uint32_t version_info;
        uint32_t fuse_mode;
    } __attribute__((packed));
    """

    def __init__(self, ver=1, md=0x9045):
        """
        Class initialisation function.
        """
        self.version = keywrlite_type_uint32_t(ver)
        self.mode = keywrlite_type_uint32_t(md)
    
    def tobin(self):
        """
        """
        retbin = b''
        retbin += self.version.tobin()
        retbin += self.mode.tobin()
        return retbin
    def getStructName(self):
        return "uboot_header"
    def getStructDeclaration(self):
        retstr = """
struct uboot_header {
    uint32_t version_info;
    uint32_t fuse_mode;
} __attribute__((packed));
        """
        return retstr
    def getObject(self):
        retstr = """
        {
            .version_info = [version],
            .fuse_mode = [mode],
        }
        """
        retstr = retstr.replace("[version]", self.version.toHexStr())
        retstr = retstr.replace("[mode]", self.mode.toHexStr())
        return retstr

def custom_message_box(app, title, message, width=40, height=10):
    # Create a Toplevel window (acts like a dialog box)
    popup = tk.Toplevel()
    popup.wm_title(title)
    # Set the initial size (width x height in pixels)
    popup.geometry(f"{width*10}x{height*20}") # approximate size based on character units

    # Create a frame to hold the Text and Scrollbar
    frame = tk.Frame(popup)
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Create a Scrollbar
    scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Create a Text widget and link it to the scrollbar
    # wrap=tk.WORD ensures that words are not cut off
    text_widget = tk.Text(frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, width=width, height=height, relief=tk.FLAT, borderwidth=0)
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    # Configure the scrollbar to work with the text widget
    scrollbar.config(command=text_widget.yview)

    # Insert the message and set the state to 'disabled' (read-only)
    text_widget.insert(tk.END, message)
    text_widget.config(state=tk.DISABLED)

    def close_dialog():
        popup.destroy()
        # --- FIX: Re-enable scrolling on the main window ---
        app.canvas.bind_all("<MouseWheel>", app.onMouseWheelWindowsLinux)  # Windows and Linux
        app.canvas.bind_all("<Button-4>", app.onMouseWheelMac)  # macOS scroll up
        app.canvas.bind_all("<Button-5>", app.onMouseWheelMac)  # macOS scroll down

    # Add an OK button
    ok_button = tk.Button(popup, text="OK", command=close_dialog, width=20)
    ok_button.pack()
    popup.protocol("WM_DELETE_WINDOW", close_dialog)

    app.canvas.unbind_all("<MouseWheel>")  # Windows and Linux
    app.canvas.unbind_all("<Button-4>")  # macOS scroll up
    app.canvas.unbind_all("<Button-5>")  # macOS scroll down

    # Make the Toplevel window stay on top of the main window
    popup.grab_set()
    popup.focus_set()
    popup.wait_window()


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20

        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)  # Remove window decorations
        self.tip_window.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tip_window, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
        self.tip_window = None

def HALF_HZ_LOOP(app):
    """
    """
    flag = False
    while True:
        err = app.validateMPKHValues()
        err += app.validateKeyCntValue()
        err += app.validateKeyRevValue()
        err += app.validateSBLSWRevValue()
        err += app.validateSYSFWSWRevValue()
        err += app.validateBRDCFGSWRevValue()
        err += app.validateMSVValue()
        err += app.validateBootModeValues()
        err += app.validateExtOtpValues()

        time.sleep(2)

        if not flag:
            app.showDisclaimer()
            flag = True

class App:
    """
    This class creates the user interface and provides methods to interact with the elements of the user interface.
    """

    def __init__(self):
        """
        Class constructor; it builds the user interface by invoking various private member methods.
        """

        #CREATE THE MAIN WINDOW FOR THE APPLICATION
        self.root0=tk.Tk()
        self.root0.title("Key Configurator [v].[s].[p]".replace("[v]",tool_version).replace("[s]", tool_subversion).replace("[p]", tool_patchversion))
        self.root0.geometry("1000x600")
        self.root0.resizable(True, True)

        self.__createMenubar()

        self.__createScrollableFrame()

        self.__createLogo()
        self.__createTopSegment0()

        self.__createTopSegment1(['-'], ['-'], 0, 0)
        
        self.__createMPKHMenu()
        self.__createKeyCntMenu()
        self.__createKeyRevMenu()
        self.__createSBLSWRevMenu()
        self.__createSYSFWSWRevMenu()
        self.__createBRDCFGSWRevMenu()
        self.__createMSVMenu()
        self.__createJTAGDisableMenu()
        self.__createBootModeMenu()
        self.__createExtOtpMenu()
        self.__createBottomSegment()

        self.__updateKeywrModeFromDevice()
        self.__updateKeywrHeaderFromDevice()

        if self.keywriter_mode_disp.get() == 1:
            self.__enableAndLockAllEnableBoxes()

        self.__revealWidgets()

        self.declarations = ""
        self.definitions = ""
        self.blob_declarations = ""

        self.two_hz_thread=threading.Thread(target = HALF_HZ_LOOP, args=(self,), daemon=True)
        self.two_hz_thread.start()
    
    #######################################################
    # FUNCTIONS TO CREATE AND INTERACT WITH WIDGETS - START
    #######################################################
    
    def __createMenubar(self):
        """
        This private method creates the menubar
        """
        self.menubar = tk.Menu(self.root0, fg="white", bg="#CC0000")
        self.root0.config(menu=self.menubar) # Attach the menubar to the window

        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.file_menu.add_command(label="Save", command=self.__saveToolState)
        self.file_menu.add_command(label="Import", command=self.__restoreToolState)

        self.help_menu = tk.Menu(self.menubar, tearoff=0)
        self.help_menu.add_command(label="action flags", command=self.__actionFlagsInfo)

        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.menubar.add_cascade(label="Help", menu=self.help_menu)

    def __createScrollableFrame(self):
        """
        This private method creates a scrollable frame
        """
        self.root0_frame = tk.Frame(self.root0)
        self.canvas = tk.Canvas(self.root0_frame, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.root0_frame, orient="vertical", command=self.canvas.yview)
        self.root = tk.Frame(self.canvas)
        
        # Configure Scrollable Frame
        self.root.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.root, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        # Bind Mouse Wheel Events
        self.canvas.bind_all("<MouseWheel>", self.onMouseWheelWindowsLinux)  # Windows and Linux
        self.canvas.bind_all("<Button-4>", self.onMouseWheelMac)  # macOS scroll up
        self.canvas.bind_all("<Button-5>", self.onMouseWheelMac)  # macOS scroll down
        # Pack Widgets
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.root0_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    def onMouseWheelWindowsLinux(self, event):
        """
        Scroll for Windows and Linux
        """
        self.canvas.yview_scroll(-1 * int(event.delta / 120), "units")

    def onMouseWheelMac(self, event):
        """
        Scroll for macOS
        """
        if event.num == 4:  # Scroll up
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:  # Scroll down
            self.canvas.yview_scroll(1, "units")
    
    def __createLogo(self):
        """
        This private method creates the application logo
        """
        self.logo = tk.PhotoImage(file='ti_logo.png')
        self.logo_label = tk.Label(self.root, image=self.logo)
        self.logo_label.pack()

        self.separator0 = ttk.Separator(self.root, orient='horizontal')
        self.separator0.pack(fill='x', pady=5)

        self.disclaimer = tk.Label(self.root, text="Disclaimer: REFERENCE USE ONLY".replace("[d]", disclaimer), fg="#c00000")
        self.disclaimer.pack(fill='x')
        ToolTip(self.disclaimer, disclaimer)

    def __createTopSegment0(self):
        """
        This private method creates a segment that is used to select keywriting mode and the device
        """
        self.top_segment_0 = tk.LabelFrame(self.root)
        self.top_segment_0.pack(expand=1, fill=tk.X, padx=5)

        self.device_section = tk.LabelFrame(self.top_segment_0, text="Device :")
        self.device_section.pack(expand=1, side=tk.LEFT, padx=5, pady=5)

        self.keywriter_mode_section = tk.LabelFrame(self.top_segment_0, text="Keywriter mode :")
        self.keywriter_mode_section.pack(expand=1, side=tk.LEFT, padx=5, pady=5)
        
        self.var_device = tk.StringVar(self.device_section)
        self.var_device.set(KEYWRITER_DEVICES[0])
        
        self.devices_menu = tk.OptionMenu(self.device_section, self.var_device, *KEYWRITER_DEVICES, command=self.__updateGUIWhenDeviceChanges)
        self.devices_menu.config(width=15)
        self.devices_menu.pack(expand=1, side=tk.LEFT, padx=5, pady=5)

        self.keywriter_mode_disp = tk.IntVar()
        self.keywriter_mode_cbox0 = tk.Radiobutton(self.keywriter_mode_section, text="Keywriter", variable=self.keywriter_mode_disp, value=0, justify="left", command=self.__updateGUIWhenKeywrModeChanges)
        self.keywriter_mode_cbox1 = tk.Radiobutton(self.keywriter_mode_section, text="Keywriter-lite", variable=self.keywriter_mode_disp, value=1, justify="left", command=self.__updateGUIWhenKeywrModeChanges)
    
    def __createTopSegment1(self, keywr_lite_versions, cmd_ids, abi_maj, abi_min):
        """
        This private method creates a top segment
        """
        self.top_segment_1 = tk.LabelFrame(self.root, text="Header")

        self.top_segment_1_frm0 = tk.Frame(self.top_segment_1)
        self.top_segment_1_frm1 = tk.Frame(self.top_segment_1)

        self.top_segment_1_frm0.pack(expand=1, fill=tk.X)
        self.top_segment_1_frm1.pack(expand=1, fill=tk.X)

        self.version_lab = tk.Label(self.top_segment_1_frm0, text="version :", width=15)

        self.abi_maj_lab = tk.Label(self.top_segment_1_frm0, text="abi major :", width=15)
        self.abi_maj_lab.pack(expand=1, side=tk.LEFT)

        self.abi_minor_lab = tk.Label(self.top_segment_1_frm0, text="abi minor :", width=15)
        self.abi_minor_lab.pack(expand=1, side=tk.LEFT)

        self.cmd_id_lab = tk.Label(self.top_segment_1_frm0, text="command id :", width=15)
        self.cmd_id_lab.pack(expand=1, side=tk.LEFT)

        self.var_keywr_lite_ver = tk.StringVar(self.top_segment_1_frm1)
        self.var_keywr_lite_ver.set(keywr_lite_versions[0])
        
        self.keywr_lite_menu = tk.OptionMenu(self.top_segment_1_frm1, self.var_keywr_lite_ver, *keywr_lite_versions, command=self.__updateGUIWhenKeywrLiteVerChanges)
        self.keywr_lite_menu.config(width=15)

        self.abi_maj_val = tk.IntVar(self.top_segment_1_frm1, abi_maj)
        self.abi_maj_menu=tk.Spinbox(self.top_segment_1_frm1, from_ = 0, to_ = 5, textvariable=self.abi_maj_val)
        self.abi_maj_menu.config(width=15)
        self.abi_maj_menu.pack(expand=1, side=tk.LEFT, padx=5, pady=5)

        self.abi_min_val = tk.IntVar(self.top_segment_1_frm1, abi_min)
        self.abi_min_menu=tk.Spinbox(self.top_segment_1_frm1, from_ = 0, to_ = 5, textvariable=self.abi_min_val)
        self.abi_min_menu.config(width=15)
        self.abi_min_menu.pack(expand=1, side=tk.LEFT, padx=5, pady=5)

        self.var_cmd_ids = tk.StringVar(self.top_segment_1_frm1)
        self.var_cmd_ids.set(cmd_ids[0])
        
        self.cmd_ids_menu = tk.OptionMenu(self.top_segment_1_frm1, self.var_cmd_ids, *cmd_ids, command=self.__updateGUIWhenCmdIdChanges)
        self.cmd_ids_menu.config(width=15)
        self.cmd_ids_menu.pack(expand=1, side=tk.LEFT, padx=5, pady=5)

    def __createMPKHMenu(self):
        """
        This private method creates a menu for command id
        """
        self.mpkh = tk.LabelFrame(self.root, text="MPKH")

        self.mpkopts_segment_frm = tk.Frame(self.mpkh)
        self.mpkopts_segment_frm.pack(expand=1, fill=tk.X)

        self.mpk_opts_lab = tk.Label(self.mpkopts_segment_frm, text="options :", width=15)
        self.mpk_opts_box = tk.Entry(self.mpkopts_segment_frm, width=30)
        self.mpk_opts_help = tk.Label(self.mpkopts_segment_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.mpk_opts_help, """
MPK (SMPKH/BMPKH) options is a 10 bit value.
It is constituted by two 5 bit values, to be programmed contiguous to MPKH part 1 and part 2.
Currently it is reserved for future use; therefore, use only value 0.
""")
        self.mpk_opts_err = tk.Label(self.mpkopts_segment_frm, text="", fg="#c00000")
        
        self.mpk_opts_lab.grid(row=0, column=0, padx=5, pady=5)
        self.mpk_opts_box.grid(row=0, column=1, padx=5, pady=5)
        self.mpk_opts_help.grid(row=0, column=2)
        self.mpk_opts_err.grid(row=1, column=0)

        self.smpkh_segment_frm = tk.LabelFrame(self.mpkh, text="SMPKH")
        self.bmpkh_segment_frm = tk.LabelFrame(self.mpkh, text="BMPKH")

        self.smpkh_segment_frm.pack(expand=1, fill=tk.X)
        self.bmpkh_segment_frm.pack(expand=1, fill=tk.X)

        self.smpkh_segment_sub_frm0 = tk.Frame(self.smpkh_segment_frm)
        self.bmpkh_segment_sub_frm0 = tk.Frame(self.bmpkh_segment_frm)

        self.smpkh_segment_sub_frm0.pack(expand=1, pady=10, fill=tk.X)
        self.bmpkh_segment_sub_frm0.pack(expand=1, pady=10, fill=tk.X)

        self.smpkh_box = tk.Entry(self.smpkh_segment_sub_frm0, width=80)
        self.smpkh_help = tk.Label(self.smpkh_segment_sub_frm0, text="?", relief="solid", borderwidth=1)
        ToolTip(self.smpkh_help, """
SMPKH represents the SHA2-512 hash of primary customer public key.
Provide the SMPKH in the form of hex string, ex: a24baf.... (128 characters.)
It is advised to Write Protect SMPKH Efuses (via write protect feature) as altering these efuses accidentally can lead to permanent failure of device boot.
""")
        self.smpkh_err = tk.Label(self.smpkh_segment_sub_frm0, text="", fg="#c00000")
        self.smpkh_button = tk.Button(self.smpkh_segment_sub_frm0, text="Load SMPKH", width=20, command=lambda: calculate_hash_from_file(self.smpkh_box))
        
        self.smpkh_box.grid(row=0, column=0)
        self.smpkh_help.grid(row=0, column=1)
        self.smpkh_button.grid(row=0, column=2)
        self.smpkh_err.grid(row=1, column=0)

        self.smpkh_action_flags_lab = tk.Label(self.smpkh_segment_frm, text="action flags :")
        self.smpkh_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.smpkh_enable = tk.IntVar()
        self.smpkh_enable_option = tk.Checkbutton(self.smpkh_segment_frm, text="Enable ", variable=self.smpkh_enable)
        self.smpkh_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.smpkh_override = tk.IntVar()
        self.smpkh_override_option = tk.Checkbutton(self.smpkh_segment_frm, text="Override", variable=self.smpkh_override)
        self.smpkh_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.smpkh_read_protect = tk.IntVar()
        self.smpkh_read_protect_option = tk.Checkbutton(self.smpkh_segment_frm, text="Read protect", variable=self.smpkh_read_protect)
        self.smpkh_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.smpkh_write_protect = tk.IntVar()
        self.smpkh_write_protect_option = tk.Checkbutton(self.smpkh_segment_frm, text="Write protect", variable=self.smpkh_write_protect)
        self.smpkh_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)

        self.bmpkh_box = tk.Entry(self.bmpkh_segment_sub_frm0, width=80)
        self.bmpkh_help = tk.Label(self.bmpkh_segment_sub_frm0, text="?", relief="solid", borderwidth=1)
        ToolTip(self.bmpkh_help, """
BMPKH represents the SHA2-512 hash of the backup customer public key.
Provide the BMPKH in the form of hex string, ex: a24baf.... (128 characters.)

Note: If required the backup key must be provisioned by Key writer lite along with primary key.
It can be activated once product is deployed in field via incremental programming of KEVREV field in field. 
If backup key is not provisioned by keywriter lite on HS-FS device then it is not possible to program it after the device transitions to HS-SE.
It is advised to Write Protect BMPKH Efuses (via write protect feature) as altering these efuses accidentally can lead to permanent failure of device boot.
""")
        self.bmpkh_button = tk.Button(self.bmpkh_segment_sub_frm0, text="Load BMPKH", width=20, command=lambda: calculate_hash_from_file(self.bmpkh_box))
        self.bmpkh_err = tk.Label(self.bmpkh_segment_sub_frm0, text="", fg="#c00000")
        
        self.bmpkh_box.grid(row=0, column=0)
        self.bmpkh_help.grid(row=0, column=1)
        self.bmpkh_button.grid(row=0, column=2)
        self.bmpkh_err.grid(row=1, column=0)

        self.bmpkh_action_flags_lab = tk.Label(self.bmpkh_segment_frm, text="action flags :")
        self.bmpkh_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.bmpkh_enable = tk.IntVar()
        self.bmpkh_enable_option = tk.Checkbutton(self.bmpkh_segment_frm, text="Enable ", variable=self.bmpkh_enable)
        self.bmpkh_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.bmpkh_override = tk.IntVar()
        self.bmpkh_override_option = tk.Checkbutton(self.bmpkh_segment_frm, text="Override", variable=self.bmpkh_override)
        self.bmpkh_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.bmpkh_read_protect = tk.IntVar()
        self.bmpkh_read_protect_option = tk.Checkbutton(self.bmpkh_segment_frm, text="Read protect", variable=self.bmpkh_read_protect)
        self.bmpkh_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.bmpkh_write_protect = tk.IntVar()
        self.bmpkh_write_protect_option = tk.Checkbutton(self.bmpkh_segment_frm, text="Write protect", variable=self.bmpkh_write_protect)
        self.bmpkh_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultMpkOpts(self):
        """
        Function to set default value in MPK Options widget.
        """
        self.mpk_opts_box.delete("0", tk.END)
        self.mpk_opts_box.insert("0", "0")

    def __setDefaultSMPKH(self):
        """
        Function to set default value in SMPKH widget.
        """
        self.smpkh_box.delete("0", tk.END)
        self.smpkh_box.insert("0", "0"*128)
    
    def __setDefaultBMPKH(self):
        """
        Function to set default value in BMPKH widget.
        """
        self.bmpkh_box.delete("0", tk.END)
        self.bmpkh_box.insert("0", "0"*128)
    
    def __getMPKOptsState(self):
        """
        Function to return MPK Options state
        """
        ret_obj = {}
        ret_obj["options"] = self.mpk_opts_box.get()
        return ret_obj
    
    def __setMPKOptsState(self, state):
        """
        Function to set MPK Options state
        """
        self.mpk_opts_box.delete("0",tk.END)
        self.mpk_opts_box.insert("0", state["options"])

    def __getMPKHState(self, smpkhFlag=True):
        """
        Function to get the MPKH state
        """
        ret_obj = {}
        if smpkhFlag:
            ret_obj["mpkh"] = self.smpkh_box.get()
            ret_obj["enable"] = self.smpkh_enable.get()
            ret_obj["override"] = self.smpkh_override.get()
            ret_obj["read-protect"] = self.smpkh_read_protect.get()
            ret_obj["write-protect"] = self.smpkh_write_protect.get()
        else:
            ret_obj["mpkh"] = self.bmpkh_box.get()
            ret_obj["enable"] = self.bmpkh_enable.get()
            ret_obj["override"] = self.bmpkh_override.get()
            ret_obj["read-protect"] = self.bmpkh_read_protect.get()
            ret_obj["write-protect"] = self.bmpkh_write_protect.get()

        return ret_obj

    def __setMPKHState(self, state, smpkhFlag=True):
        """
        Function to get the MPKH state
        """
        if smpkhFlag:
            self.smpkh_box.delete(0,tk.END)
            self.smpkh_box.insert("0", state["mpkh"])
            self.smpkh_enable.set(state["enable"])
            self.smpkh_override.set(state["override"])
            self.smpkh_read_protect.set(state["override"])
            self.smpkh_write_protect.set(state["write-protect"])
        else:
            self.bmpkh_box.delete(0,tk.END)
            self.bmpkh_box.insert("0", state["mpkh"])
            self.bmpkh_enable.set(state["enable"])
            self.bmpkh_override.set(state["override"])
            self.bmpkh_read_protect.set(state["read-protect"])
            self.bmpkh_write_protect.set(state["write-protect"])

    def validateMPKHValues(self, check_empty=False):
        """
        Function to validate MPKH Values
        """
        err = ""
        ret_err = ""

        cmd_id = self.var_cmd_ids.get()

        if cmd_id == "one-shot" or cmd_id == "smpkh" or cmd_id == "bmpkh" or cmd_id == "multi-shot":
            opts = self.mpk_opts_box.get().strip()

            if len(opts) == 0:
                if check_empty:
                    err += "No MPK Options"
            elif not str_is_hex(opts):
                err += "MPK Options not hex"
            elif int(opts, 16).bit_length() > 10:
                err += "MPK Options bigger than 10 bits"
            elif int(opts, 16) != 0:
                err += "Since MPK Options field is reserved, it must be 0"
            
        if err != "":
            ret_err += err + '\n'
            self.mpk_opts_err.config(text=err)
        else:
            self.mpk_opts_err.config(text="")
        err=""

        if cmd_id == "one-shot" or cmd_id == "smpkh" or cmd_id == "multi-shot":
            mpkh = self.smpkh_box.get().strip()

            if len(mpkh) == 0:
                if check_empty:
                    err += "No SMPKH"
            elif not str_is_hex(mpkh):
                err += "SMPKH not hex"
            elif len(mpkh) != 128:
                err += "SMPKH Invalid Length"
        
        if err != "":
            ret_err += err + '\n'
            self.smpkh_err.config(text=err)
        else:
            self.smpkh_err.config(text="")
        err=""
        
        if cmd_id == "one-shot" or cmd_id == "bmpkh" or cmd_id == "multi-shot":
            mpkh = self.bmpkh_box.get().strip()

            if len(mpkh) == 0:
                if check_empty:
                    err += "No BMPKH"
            elif not str_is_hex(mpkh):
                err += "BMPKH not hex"
            elif len(mpkh) != 128:
                err += "BMPKH Invalid Length"
        
        if err != "":
            ret_err += err + '\n'
            self.bmpkh_err.config(text=err)
        else:
            self.bmpkh_err.config(text="")
        err=""
        
        return ret_err
    
    def __createKeyCntMenu(self):
        """
        This private method creates the menu to provide key count value
        """
        self.key_cnt = tk.LabelFrame(self.root, text="Key Count")

        self.key_cnt_frm = tk.Frame(self.key_cnt)
        self.key_cnt_frm.pack(expand=1, fill=tk.X)

        self.key_cnt_val = tk.IntVar(self.key_cnt_frm, 1)
        self.key_cnt_menu=tk.Spinbox(self.key_cnt_frm, from_ = 1, to_ = 2, width=30, textvariable=self.key_cnt_val)
        self.key_cnt_help = tk.Label(self.key_cnt_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.key_cnt_help, """
Represents the number of active keys provisioned in the device, and supports following values:

- 1 if only Primary Key (SMPKH) has to be provisioned

- 2 if both Primary Key (SMPKH) and Backup Key (BMPKH) have to be provisioned

Note: This field will control the active Key sets in the device, if user wants to enable backup Key it is mandatory to provision backup key and set KEYCNT as 2 through Keywriter lite.
      If this field is programmed as 1 then device can only support primary Key for Secure boot and this field can not be updated later.

It is advised to Write Protect KEYCNT efuses as altering these efuses accidentally can lead to permanent failure of device boot.
""")
        self.key_cnt_err=tk.Label(self.key_cnt_frm, text="", fg="#c00000")
        self.key_cnt_menu.grid(row=0, column=0, padx=10)
        self.key_cnt_help.grid(row=0, column=1)
        self.key_cnt_err.grid(row=1, column=0, padx=10)

        self.key_cnt_action_flags_lab = tk.Label(self.key_cnt, text="action flags :")
        self.key_cnt_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_cnt_enable = tk.IntVar()
        self.key_cnt_enable_option = tk.Checkbutton(self.key_cnt, text="Enable ", variable=self.key_cnt_enable)
        self.key_cnt_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_cnt_override = tk.IntVar()
        self.key_cnt_override_option = tk.Checkbutton(self.key_cnt, text="Override", variable=self.key_cnt_override)
        self.key_cnt_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_cnt_read_protect = tk.IntVar()
        self.key_cnt_read_protect_option = tk.Checkbutton(self.key_cnt, text="Read protect", variable=self.key_cnt_read_protect)
        self.key_cnt_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_cnt_write_protect = tk.IntVar()
        self.key_cnt_write_protect_option = tk.Checkbutton(self.key_cnt, text="Write protect", variable=self.key_cnt_write_protect)
        self.key_cnt_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultKeyCnt(self):
        """
        Function to default value in key count value.
        """
        self.key_cnt_val.set(1)

    def __getKeyCntState(self):
        """
        Function to get key count widget state.
        """
        ret_obj = {}
        ret_obj["count"] = self.key_cnt_menu.get()
        ret_obj["enable"] = self.key_cnt_enable.get()
        ret_obj["override"] = self.key_cnt_override.get()
        ret_obj["read-protect"] = self.key_cnt_read_protect.get()
        ret_obj["write-protect"] = self.key_cnt_write_protect.get()
        return ret_obj
    
    def __setKeyCntState(self, state):
        """
        Function to set key count widget state.
        """
        self.key_cnt_val.set(state["count"])
        self.key_cnt_enable.set(state["enable"])
        self.key_cnt_override.set(state["override"])
        self.key_cnt_read_protect.set(state["read-protect"])
        self.key_cnt_write_protect.set(state["write-protect"])

    def validateKeyCntValue(self, check_empty=False):
        """
        Function to validate key count value
        """
        err = ""
        cmd_id = self.var_cmd_ids.get()

        if cmd_id == "one-shot" or cmd_id == "key-cnt" or cmd_id == "multi-shot":
            key_cnt = self.key_cnt_menu.get().strip()

            if key_cnt == "":
                if check_empty:
                    err += "No Key Count Value"
            else:
                if not str_is_int(key_cnt):
                    err += "Invalid key count"
                elif int(key_cnt) < 1:
                    err += "Key Count cannot be 0"
                elif int(key_cnt) > 2:
                    err += "Key Count cannot be more than 2"
            
            if err != "":
                self.key_cnt_err.config(text=err)
                err += '\n'
            else:
                self.key_cnt_err.config(text="")
        
        return err
    
    def __createKeyRevMenu(self):
        """
        This private method creates the menu to provide key revision value
        """
        self.key_rev = tk.LabelFrame(self.root, text="Key Revision")

        self.key_rev_frm = tk.Frame(self.key_rev)
        self.key_rev_frm.pack(expand=1, fill=tk.X)

        self.key_rev_val = tk.IntVar(self.key_rev_frm, 1)
        self.key_rev_menu=tk.Spinbox(self.key_rev_frm, from_ = 1, to_ = 2, width=30, textvariable=self.key_rev_val)
        self.key_rev_help = tk.Label(self.key_rev_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.key_rev_help, """
Represents the active public key:

- 1 for Primary Key (SMPKH)

- 2 for Backup Key (BMPKH)

It is NOT recommended to Write Protect KEYREV efuses  as this field may be incremented during the life time of device to change Root Of Trust.

KEYREV value should always be less than or equal to KEYCNT

Note: Once this field is programmed device will transition from HS-FS to HS-SE and keywriter lite cant be used after that.
    This field should be programmed as the last field.
""")
        self.key_rev_err=tk.Label(self.key_rev_frm, text="", fg="#c00000")
        self.key_rev_menu.grid(row=0, column=0, padx=10)
        self.key_rev_help.grid(row=0, column=1)
        self.key_rev_err.grid(row=1, column=0, padx=10)

        self.key_rev_action_flags_lab = tk.Label(self.key_rev, text="action flags :")
        self.key_rev_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_rev_enable = tk.IntVar()
        self.key_rev_enable_option = tk.Checkbutton(self.key_rev, text="Enable ", variable=self.key_rev_enable)
        self.key_rev_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_rev_override = tk.IntVar()
        self.key_rev_override_option = tk.Checkbutton(self.key_rev, text="Override", variable=self.key_rev_override)
        self.key_rev_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_rev_read_protect = tk.IntVar()
        self.key_rev_read_protect_option = tk.Checkbutton(self.key_rev, text="Read protect", variable=self.key_rev_read_protect)
        self.key_rev_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.key_rev_write_protect = tk.IntVar()
        self.key_rev_write_protect_option = tk.Checkbutton(self.key_rev, text="Write protect", variable=self.key_rev_write_protect)
        self.key_rev_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultKeyRev(self):
        """
        Function to set default value in key revision value.
        """
        self.key_rev_val.set(1)
    
    def __getKeyRevState(self):
        """
        Function to get key revision widget state.
        """
        ret_obj = {}
        ret_obj["revision"] = self.key_rev_menu.get()
        ret_obj["enable"] = self.key_rev_enable.get()
        ret_obj["override"] = self.key_rev_override.get()
        ret_obj["read-protect"] = self.key_rev_read_protect.get()
        ret_obj["write-protect"] = self.key_rev_write_protect.get()
        return ret_obj
    
    def __setKeyRevState(self, state):
        """
        Function to set key revision widget state.
        """
        self.key_rev_val.set(state["revision"])
        self.key_rev_enable.set(state["enable"])
        self.key_rev_override.set(state["override"])
        self.key_rev_read_protect.set(state["read-protect"])
        self.key_rev_write_protect.set(state["write-protect"])

    def validateKeyRevValue(self, check_empty=False):
        """
        Function to validate key revision value
        """
        err = ""
        cmd_id = self.var_cmd_ids.get()

        if cmd_id == "one-shot" or cmd_id == "key-rev" or cmd_id == "multi-shot":
            key_rev = self.key_rev_menu.get().strip()
            key_cnt = self.key_cnt_menu.get().strip()

            if key_rev == "":
                if check_empty:
                    err += "No Key Revision Value"
            else:
                if not str_is_int(key_rev):
                    err += "Invalid Key Revision"
                elif int(key_rev) < 1:
                    err += "Key Revision cannot be 0"
                elif int(key_rev) > 2:
                    err += "Key Revision cannot be more than 2"
                elif str_is_int(key_cnt):
                    if int(key_rev) > int(key_cnt):
                        err += "Key Rev greater than Key Cnt"
            
            if err != "":
                self.key_rev_err.config(text=err)
                err += '\n'
            else:
                self.key_rev_err.config(text="")
        
        return err

    def __createSBLSWRevMenu(self):
        """
        This private method creates the menu to provide sbl swrev value
        """
        self.sbl_swrev = tk.LabelFrame(self.root, text="SBL Software Revision")

        self.sbl_swrev_frm = tk.Frame(self.sbl_swrev)
        self.sbl_swrev_frm.pack(expand=1, fill=tk.X)

        self.sbl_swrev_val = tk.IntVar(self.sbl_swrev_frm, 1)
        self.sbl_swrev_menu=tk.Spinbox(self.sbl_swrev_frm, from_ = 1, to_ = 48, width=30, textvariable=self.sbl_swrev_val)
        self.sbl_swrev_help = tk.Label(self.sbl_swrev_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.sbl_swrev_help, """
Represents SBL software revision, a 96 bit value (48 without double redundancy)

It is NOT recommended to Write Protect SWREV efuses as this field can be incremented during the life time of device to enforce anti Roll back.
It is mandatory to set override flag to update this field.
""")
        self.sbl_swrev_err=tk.Label(self.sbl_swrev_frm, text="", fg="#c00000")
        self.sbl_swrev_menu.grid(row=0, column=0, padx=10)
        self.sbl_swrev_help.grid(row=0, column=1)
        self.sbl_swrev_err.grid(row=1, column=0, padx=10)

        self.sbl_swrev_action_flags_lab = tk.Label(self.sbl_swrev, text="action flags :")
        self.sbl_swrev_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.sbl_swrev_enable = tk.IntVar()
        self.sbl_swrev_enable_option = tk.Checkbutton(self.sbl_swrev, text="Enable ", variable=self.sbl_swrev_enable)
        self.sbl_swrev_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.sbl_swrev_override = tk.IntVar()
        self.sbl_swrev_override_option = tk.Checkbutton(self.sbl_swrev, text="Override", variable=self.sbl_swrev_override)
        self.sbl_swrev_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.sbl_swrev_read_protect = tk.IntVar()
        self.sbl_swrev_read_protect_option = tk.Checkbutton(self.sbl_swrev, text="Read protect", variable=self.sbl_swrev_read_protect)
        self.sbl_swrev_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.sbl_swrev_write_protect = tk.IntVar()
        self.sbl_swrev_write_protect_option = tk.Checkbutton(self.sbl_swrev, text="Write protect", variable=self.sbl_swrev_write_protect)
        self.sbl_swrev_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultSBLSWRev(self):
        """
        Function to set default value in sbl software revision widget.
        """
        self.sbl_swrev_val.set(1)

    def __getSBLSWRevState(self):
        """
        Function to get the SBL software revision widget state.
        """
        ret_obj = {}
        ret_obj["revision"] = self.sbl_swrev_menu.get()
        ret_obj["enable"] = self.sbl_swrev_enable.get()
        ret_obj["override"] = self.sbl_swrev_override.get()
        ret_obj["read-protect"] = self.sbl_swrev_read_protect.get()
        ret_obj["write-protect"] = self.sbl_swrev_write_protect.get()
        return ret_obj
    
    def __setSBLSWRevState(self, state):
        """
        Function to set the SBL software widget revision state.
        """
        self.sbl_swrev_val.set(state["revision"])
        self.sbl_swrev_enable.set(state["enable"])
        self.sbl_swrev_override.set(state["override"])
        self.sbl_swrev_read_protect.set(state["read-protect"])
        self.sbl_swrev_write_protect.set(state["write-protect"])
    
    def validateSBLSWRevValue(self, check_empty=False):
        """
        Function to validate sbl software revision value.
        """
        err = ""
        cmd_id = self.var_cmd_ids.get()

        if cmd_id == "one-shot" or cmd_id == "sbl-swrev" or cmd_id == "multi-shot":
            sbl_swrev = self.sbl_swrev_menu.get().strip()

            if sbl_swrev == "":
                if check_empty:
                    err += "No SBL SWRev Value"
            else:
                if not str_is_int(sbl_swrev):
                    err += "Invalid SBL SWRev Revision"
                elif int(sbl_swrev) < 1:
                    err += "SBL SWRev cannot be 0"
                elif int(sbl_swrev) > 48:
                    err += "SBL SWRev cannot be more than 48"
            
            if err != "":
                self.sbl_swrev_err.config(text=err)
                err += '\n'
            else:
                self.sbl_swrev_err.config(text="")
        
        return err
    
    def __createSYSFWSWRevMenu(self):
        """
        This private method creates the menu to provide sysfw swrev value.
        """
        self.sysfw_swrev = tk.LabelFrame(self.root, text="SysFw Software Revision")

        self.sysfw_swrev_frm = tk.Frame(self.sysfw_swrev)
        self.sysfw_swrev_frm.pack(expand=1, fill=tk.X)

        self.sysfw_swrev_val = tk.IntVar(self.sysfw_swrev_frm, 1)
        self.sysfw_swrev_menu=tk.Spinbox(self.sysfw_swrev_frm, from_ = 1, to_ = 48, width=30, textvariable=self.sysfw_swrev_val)
        self.sysfw_swrev_help = tk.Label(self.sysfw_swrev_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.sysfw_swrev_help, """
Represents SYSFW software revision, a 96 bit value (48 without double redundancy)

It is NOT recommended to Write Protect SWREV efuses as this field can be incremented during the life time of device to enforce anti Roll back.
It is mandatory to set override flag to update this field.
""")
        self.sysfw_swrev_err=tk.Label(self.sysfw_swrev_frm, text="", fg="#c00000")
        self.sysfw_swrev_menu.grid(row=0, column=0, padx=10)
        self.sysfw_swrev_help.grid(row=0, column=1)
        self.sysfw_swrev_err.grid(row=1, column=0, padx=10)

        self.sysfw_swrev_action_flags_lab = tk.Label(self.sysfw_swrev, text="action flags :")
        self.sysfw_swrev_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.sysfw_swrev_enable = tk.IntVar()
        self.sysfw_swrev_enable_option = tk.Checkbutton(self.sysfw_swrev, text="Enable ", variable=self.sysfw_swrev_enable)
        self.sysfw_swrev_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.sysfw_swrev_override = tk.IntVar()
        self.sysfw_swrev_override_option = tk.Checkbutton(self.sysfw_swrev, text="Override", variable=self.sysfw_swrev_override)
        self.sysfw_swrev_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.sysfw_swrev_read_protect = tk.IntVar()
        self.sysfw_swrev_read_protect_option = tk.Checkbutton(self.sysfw_swrev, text="Read protect", variable=self.sysfw_swrev_read_protect)
        self.sysfw_swrev_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.sysfw_swrev_write_protect = tk.IntVar()
        self.sysfw_swrev_write_protect_option = tk.Checkbutton(self.sysfw_swrev, text="Write protect", variable=self.sysfw_swrev_write_protect)
        self.sysfw_swrev_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultSYSFWSWRev(self):
        """
        Function to set default value in sysfw software revision widget.
        """
        self.sysfw_swrev_val.set(1)
    
    def __getSYSFWSWRevState(self):
        """
        Function to get the sysfw software revision widget state.
        """
        ret_obj = {}
        ret_obj["revision"] = self.sysfw_swrev_menu.get()
        ret_obj["enable"] = self.sysfw_swrev_enable.get()
        ret_obj["override"] = self.sysfw_swrev_override.get()
        ret_obj["read-protect"] = self.sysfw_swrev_read_protect.get()
        ret_obj["write-protect"] = self.sysfw_swrev_write_protect.get()
        return ret_obj
    
    def __setSYSFWSWRevState(self, state):
        """
        Function to set the sysfw software revision widget state.
        """
        self.sysfw_swrev_val.set(state["revision"])
        self.sysfw_swrev_enable.set(state["enable"])
        self.sysfw_swrev_override.set(state["override"])
        self.sysfw_swrev_read_protect.set(state["read-protect"])
        self.sysfw_swrev_write_protect.set(state["write-protect"])
    
    def validateSYSFWSWRevValue(self, check_empty=False):
        """
        Function to sysfw software revision value
        """
        err = ""
        cmd_id = self.var_cmd_ids.get()

        if cmd_id == "one-shot" or cmd_id == "sysfw-swrev" or cmd_id == "multi-shot":
            sysfw_swrev = self.sysfw_swrev_menu.get().strip()

            if sysfw_swrev == "":
                if check_empty:
                    err += "No SYSFW SWRev Value"
            else:
                if not str_is_int(sysfw_swrev):
                    err += "Invalid SYSFW SWRev Revision"
                elif int(sysfw_swrev) < 1:
                    err += "SYSFW SWRev cannot be 0"
                elif int(sysfw_swrev) > 48:
                    err += "SYSFW SWRev cannot be more than 48"
            
            if err != "":
                self.sysfw_swrev_err.config(text=err)
                err += '\n'
            else:
                self.sysfw_swrev_err.config(text="")
        
        return err
    
    def __createBRDCFGSWRevMenu(self):
        """
        This private method creates the menu to provide boardcfg swrev value
        """
        self.brdcfg_swrev = tk.LabelFrame(self.root, text="Board-Config Software Revision")

        self.brdcfg_swrev_frm = tk.Frame(self.brdcfg_swrev)
        self.brdcfg_swrev_frm.pack(expand=1, fill=tk.X)

        self.brdcfg_swrev_val = tk.IntVar(self.brdcfg_swrev_frm, 1)
        self.brdcfg_swrev_menu=tk.Spinbox(self.brdcfg_swrev_frm, from_ = 1, to_ = 64, width=30, textvariable=self.brdcfg_swrev_val)
        self.brdcfg_swrev_help = tk.Label(self.brdcfg_swrev_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.brdcfg_swrev_help, """
Represents boardconfig software revision, a 128 bit value (64 without double redundancy).

It is NOT recommended to Write Protect SWREV efuses as this field can be incremented during the life time of device to enforce anti Roll back.
It is mandatory to enable override.
""")
        self.brdcfg_swrev_err=tk.Label(self.brdcfg_swrev_frm, text="", fg="#c00000")
        self.brdcfg_swrev_menu.grid(row=0, column=0, padx=10)
        self.brdcfg_swrev_help.grid(row=0, column=1)
        self.brdcfg_swrev_err.grid(row=1, column=0, padx=10)

        self.brdcfg_swrev_action_flags_lab = tk.Label(self.brdcfg_swrev, text="action flags :")
        self.brdcfg_swrev_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.brdcfg_swrev_enable = tk.IntVar()
        self.brdcfg_swrev_enable_option = tk.Checkbutton(self.brdcfg_swrev, text="Enable ", variable=self.brdcfg_swrev_enable)
        self.brdcfg_swrev_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.brdcfg_swrev_override = tk.IntVar()
        self.brdcfg_swrev_override_option = tk.Checkbutton(self.brdcfg_swrev, text="Override", variable=self.brdcfg_swrev_override)
        self.brdcfg_swrev_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.brdcfg_swrev_read_protect = tk.IntVar()
        self.brdcfg_swrev_read_protect_option = tk.Checkbutton(self.brdcfg_swrev, text="Read protect", variable=self.brdcfg_swrev_read_protect)
        self.brdcfg_swrev_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.brdcfg_swrev_write_protect = tk.IntVar()
        self.brdcfg_swrev_write_protect_option = tk.Checkbutton(self.brdcfg_swrev, text="Write protect", variable=self.brdcfg_swrev_write_protect)
        self.brdcfg_swrev_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultBRDCFGSWRev(self):
        """
        Function to set default value in bardconfig revision widget.
        """
        self.brdcfg_swrev_val.set(1)
    
    def __getBRDCFGSWRevState(self):
        """
        Function to get the boardconfig software revision widget state.
        """
        ret_obj = {}
        ret_obj["revision"] = self.brdcfg_swrev_menu.get()
        ret_obj["enable"] = self.brdcfg_swrev_enable.get()
        ret_obj["override"] = self.brdcfg_swrev_override.get()
        ret_obj["read-protect"] = self.brdcfg_swrev_read_protect.get()
        ret_obj["write-protect"] = self.brdcfg_swrev_write_protect.get()
        return ret_obj
    
    def __setBRDCFGSWRevState(self, state):
        """
        Function to set the boardconfig software revision widget state.
        """
        self.brdcfg_swrev_val.set(state["revision"])
        self.brdcfg_swrev_enable.set(state["enable"])
        self.brdcfg_swrev_override.set(state["override"])
        self.brdcfg_swrev_read_protect.set(state["read-protect"])
        self.brdcfg_swrev_write_protect.set(state["write-protect"])
    
    def validateBRDCFGSWRevValue(self, check_empty=False):
        """
        Function to boardcfg software revision value
        """
        err = ""
        cmd_id = self.var_cmd_ids.get()

        if cmd_id == "one-shot" or cmd_id == "brdcfg-swrev" or cmd_id == "multi-shot":
            brdcfg_swrev = self.brdcfg_swrev_menu.get().strip()

            if brdcfg_swrev == "":
                if check_empty:
                    err += "No BRDCFG SWRev Value"
            else:
                if not str_is_int(brdcfg_swrev):
                    err += "Invalid BRDCFG SWRev Revision"
                elif int(brdcfg_swrev) < 1:
                    err += "BRDCFG SWRev cannot be 0"
                elif int(brdcfg_swrev) > 64:
                    err += "BRDCFG SWRev cannot be more than 64"
            
            if err != "":
                self.brdcfg_swrev_err.config(text=err)
                err += '\n'
            else:
                self.brdcfg_swrev_err.config(text="")
        
        return err

    def __createMSVMenu(self):
        """
        This private method creates a menu that can be used to provide msv value
        """
        self.msv = tk.LabelFrame(self.root, text="Model Specific Value (MSV)")

        self.msv_frm = tk.Frame(self.msv)
        self.msv_frm.pack(expand=1, fill=tk.X)

        self.msv_menu=tk.Entry(self.msv_frm, width=30)
        self.msv_help = tk.Label(self.msv_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.msv_help, """
20 bit Model Specific Value.
Customers can program 20 bit values to differentiate product variants using same SoC either in production flow Or in boot flow of the device.
""")
        self.msv_err=tk.Label(self.msv_frm, text="", fg="#c00000")
        self.msv_menu.grid(row=0, column=0, padx=10)
        self.msv_help.grid(row=0, column=1)
        self.msv_err.grid(row=1, column=0, padx=10)

        self.msv_action_flags_lab = tk.Label(self.msv, text="action flags :")
        self.msv_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.msv_enable = tk.IntVar()
        self.msv_enable_option = tk.Checkbutton(self.msv, text="Enable ", variable=self.msv_enable)
        self.msv_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.msv_override = tk.IntVar()
        self.msv_override_option = tk.Checkbutton(self.msv, text="Override", variable=self.msv_override)
        self.msv_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.msv_read_protect = tk.IntVar()
        self.msv_read_protect_option = tk.Checkbutton(self.msv, text="Read protect", variable=self.msv_read_protect)
        self.msv_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.msv_write_protect = tk.IntVar()
        self.msv_write_protect_option = tk.Checkbutton(self.msv, text="Write protect", variable=self.msv_write_protect)
        self.msv_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultMSV(self):
        """
        Function to set default value in the MSV widget.
        """
        self.msv_menu.delete("0", tk.END)
        self.msv_menu.insert("0", "0")
    
    def __getMSVState(self):
        """
        Function to get the MSV widget state.
        """
        ret_obj = {}
        ret_obj["val"] = self.msv_menu.get()
        ret_obj["enable"] = self.msv_enable.get()
        ret_obj["override"] = self.msv_override.get()
        ret_obj["read-protect"] = self.msv_read_protect.get()
        ret_obj["write-protect"] = self.msv_write_protect.get()
        return ret_obj
    
    def __setMSVState(self, state):
        """
        Function to set the MSV widget state.
        """
        self.msv_menu.delete(0, tk.END)
        self.msv_menu.insert("0", state["val"])
        self.msv_enable.set(state["enable"])
        self.msv_override.set(state["override"])
        self.msv_read_protect.set(state["read-protect"])
        self.msv_write_protect.set(state["write-protect"])
    
    def validateMSVValue(self, check_empty=False):
        """
        Function to validate MSV value.
        """
        err = ""

        cmd_id = self.var_cmd_ids.get()
        #msv_en = self.msv_enable.get()

        if cmd_id == "one-shot" or cmd_id == "msv" or cmd_id == "multi-shot":
            msv = self.msv_menu.get().strip()

            if len(msv) == 0:
                if check_empty:
                    err += "No MSV"
            elif not str_is_hex(msv):
                err += "MPK Options not hex"
            elif int(msv, 16).bit_length() > 20:
                err += "MSV bigger than 20 bits"
        
        if err != "":
            self.msv_err.config(text=err)
            err += '\n'
        else:
            self.msv_err.config(text="")
        
        return err

    def __createJTAGDisableMenu(self):
        """
        This private method creates a menu that can be used to insert jtag unlock disable field
        """
        self.jtag_disable = tk.LabelFrame(self.root, text="JTAG Unlock Disable")

        self.jtag_disable_help = tk.Label(self.jtag_disable, text="?", relief="solid", borderwidth=1)
        ToolTip(self.jtag_disable_help, """
JTAG-DISABLE once programmed forces the device into an irreversible state in which the user cannot connect to it using jtag.
There is no input text box because the tool itself determines the right value based on enable flag.
""")
        self.jtag_disable_help.pack(side="right", padx=5)

        self.jtag_disable_err=tk.Label(self.jtag_disable, text="", fg="#c00000")
        self.jtag_disable_err.pack()

        self.jtag_disable_action_flags_lab = tk.Label(self.jtag_disable, text="action flags :")
        self.jtag_disable_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.jtag_disable_enable = tk.IntVar()
        self.jtag_disable_enable_option = tk.Checkbutton(self.jtag_disable, text="Enable ", variable=self.jtag_disable_enable)
        self.jtag_disable_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.jtag_disable_override = tk.IntVar()
        self.jtag_disable_override_option = tk.Checkbutton(self.jtag_disable, text="Override", variable=self.jtag_disable_override)
        self.jtag_disable_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.jtag_disable_read_protect = tk.IntVar()
        self.jtag_disable_read_protect_option = tk.Checkbutton(self.jtag_disable, text="Read protect", variable=self.jtag_disable_read_protect)
        self.jtag_disable_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.jtag_disable_write_protect = tk.IntVar()
        self.jtag_disable_write_protect_option = tk.Checkbutton(self.jtag_disable, text="Write protect", variable=self.jtag_disable_write_protect)
        self.jtag_disable_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __getJTAGDisableState(self):
        """
        Function to get the state of JTAG Disable widget state.
        """
        ret_obj = {}
        ret_obj["enable"] = self.jtag_disable_enable.get()
        ret_obj["override"] = self.jtag_disable_override.get()
        ret_obj["read-protect"] = self.jtag_disable_read_protect.get()
        ret_obj["write-protect"] = self.jtag_disable_write_protect.get()
        return ret_obj
    
    def __setJTAGDisableState(self, state):
        """
        Function to set the state of the JTAG Disable widget state.
        """
        self.jtag_disable_enable.set(state["enable"])
        self.jtag_disable_override.set(state["override"])
        self.jtag_disable_read_protect.set(state["read-protect"])
        self.jtag_disable_write_protect.set(state["write-protect"])
    
    def validateJTAGDisableValue(self, check_empty=False):
        """
        Function to validate jtag-disable field.
        """
        err = ""
        return err
    
    def __createBootModeMenu(self):
        """
        This private method creates a menu that can be used to provide boot mode value.
        """
        self.boot_mode = tk.LabelFrame(self.root, text="Boot Mode")

        self.boot_mode_frm = tk.Frame(self.boot_mode)
        self.boot_mode_frm.pack(expand=1, fill=tk.X)

        self.fuse_idx_lab = tk.Label(self.boot_mode_frm, text="fuse index :", width=10)
        self.fuse_idx_lab.grid(row=0, column=0, padx=10)

        self.fuse_id_val=tk.IntVar(self.boot_mode_frm, 1)
        self.fuse_id_menu=tk.Spinbox(self.boot_mode_frm, from_=1, to_=2, width=30, textvariable=self.fuse_id_val)
        self.fuse_id_menu.grid(row=0, column=1, padx=10)

        self.boot_mode_lab = tk.Label(self.boot_mode_frm, text="mode :", width=10)
        self.boot_mode_lab.grid(row=0, column=2, padx=10)

        self.boot_mode_menu=tk.Entry(self.boot_mode_frm, width=30)
        self.boot_mode_help = tk.Label(self.boot_mode_frm, text="?", relief="solid", borderwidth=1)
        ToolTip(self.boot_mode_help, """
The boot mode value is a 25-bits value that must be specified as a hex string.
Boot mode values are programmed into the boot mode efuses present on devices (that have boot mode efuses)
to support reduced boot pin mode feature. The programmed value controls the device boot mode when it is
put in reduced boot mode.
""")
        self.boot_mode_menu.grid(row=0, column=3, padx=10)
        self.boot_mode_help.grid(row=0, column=4)

        self.boot_mode_err=tk.Label(self.boot_mode_frm, text="", fg="#c00000")
        self.boot_mode_err.grid(row=1, column=0, padx=10)

        self.boot_mode_action_flags_lab = tk.Label(self.boot_mode, text="action flags :")
        self.boot_mode_action_flags_lab.pack(expand=1, padx=2, side=tk.LEFT)
        self.boot_mode_enable = tk.IntVar()
        self.boot_mode_enable_option = tk.Checkbutton(self.boot_mode, text="Enable ", variable=self.boot_mode_enable)
        self.boot_mode_enable_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.boot_mode_override = tk.IntVar()
        self.boot_mode_override_option = tk.Checkbutton(self.boot_mode, text="Override", variable=self.boot_mode_override)
        self.boot_mode_override_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.boot_mode_read_protect = tk.IntVar()
        self.boot_mode_read_protect_option = tk.Checkbutton(self.boot_mode, text="Read protect", variable=self.boot_mode_read_protect)
        self.boot_mode_read_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
        self.boot_mode_write_protect = tk.IntVar()
        self.boot_mode_write_protect_option = tk.Checkbutton(self.boot_mode, text="Write protect", variable=self.boot_mode_write_protect)
        self.boot_mode_write_protect_option.pack(expand=1, padx=2, side=tk.LEFT)
    
    def __setDefaultBootMode(self):
        """
        Function to set default values in boot mode widget.
        """
        self.fuse_id_val.set(1)
        self.boot_mode_menu.delete("0", tk.END)
        self.boot_mode_menu.insert("0", "0")
    
    def __getBootModeState(self):
        """
        Function to get the state of Boot Mode widget.
        """
        ret_obj = {}
        ret_obj["fuse-id"] = self.fuse_id_menu.get()
        ret_obj["boot-mode"] = self.boot_mode_menu.get()
        ret_obj["enable"] = self.boot_mode_enable.get()
        ret_obj["override"] = self.boot_mode_override.get()
        ret_obj["read-protect"] = self.boot_mode_read_protect.get()
        ret_obj["write-protect"] = self.boot_mode_write_protect.get()
        return ret_obj
    
    def __setBootModeState(self, state):
        """
        Function to set the state of Boot Mode widget.
        """
        self.fuse_id_val.set(state["fuse-id"])
        self.boot_mode_menu.delete(0,tk.END)
        self.boot_mode_menu.insert("0", state["boot-mode"])
        self.boot_mode_enable.set(state["enable"])
        self.boot_mode_override.set(state["override"])
        self.boot_mode_read_protect.set(state["read-protect"])
        self.boot_mode_write_protect.set(state["write-protect"])

    def validateBootModeValues(self, check_empty=False):
        """
        Function to validate boot mode values
        """
        err = ""

        cmd_id = self.var_cmd_ids.get()
        #bm_en = self.boot_mode_enable.get()

        if cmd_id == "one-shot" or cmd_id == "boot-mode" or cmd_id == "multi-shot":
            bm = self.boot_mode_menu.get().strip()

            if len(bm) == 0:
                if check_empty:
                    err += "No Boot Mode Value"
            elif not str_is_hex(bm):
                err += "Boot Mode not hex"
            elif int(bm, 16).bit_length() > 25:
                err += "Boot Mode value bigger than 25 bits"
        
        if err != "":
            self.boot_mode_err.config(text=err)
            err += '\n'
        else:
            self.boot_mode_err.config(text="")
        
        return err
    
    def __createExtOtpMenu(self):
        """
        Function to create extended OTP widget
        """
        self.ext_otp = tk.LabelFrame(self.root, text="Extended OTP")

        self.ext_otp_frm00 = tk.Frame(self.ext_otp)
        self.ext_otp_frm00.pack(expand=1, fill=tk.X)

        self.ext_otp_size_lab = tk.Label(self.ext_otp_frm00, text="size (bits):")
        self.ext_otp_size_lab.grid(row=0, column=0)
        self.ext_otp_size_val=tk.IntVar(self.ext_otp_frm00, 1)
        self.ext_otp_size=tk.Spinbox(self.ext_otp_frm00, width=30, from_= 1, to_=1024, textvariable=self.ext_otp_size_val)
        self.ext_otp_size.grid(row=0, column=1, pady=1)
        self.ext_otp_index_lab = tk.Label(self.ext_otp_frm00, text="index (bits):")
        self.ext_otp_index_lab.grid(row=0, column=2)
        self.ext_otp_index_val=tk.IntVar(self.ext_otp_frm00, 0)
        self.ext_otp_index=tk.Spinbox(self.ext_otp_frm00, width=30, from_=0, to=1023, textvariable=self.ext_otp_index_val)
        self.ext_otp_index.grid(row=0, column=3, pady=1)

        self.ext_otp_help = tk.Label(self.ext_otp_frm00, text="?", relief="solid", borderwidth=1)
        ToolTip(self.ext_otp_help, """
Devices are equipped with a designated set of One-Time Programmable (OTP) eFuses intended for customer general-purpose utilization.
These specific eFuses are designated as 'extended OTP'.

Each eFuse row comprises of 25 bits.
The One-Time Programmable Memory-Mapped Registers (OTP MMRs) each contain 32 bits, which are populated sequentially from the eFuse rows in a contiguous arrangement.

Users have the capability to program and retrieve up to 1024 bits of data from these eFuses.
The requisite data may be entered via the 32 text boxes provided, with each text box corresponding to a specific 32-bit Memory-Mapped Register (MMR) within the extended OTP data section.

Furthermore, users have the option to implement read protection and/or write protection for the extended OTP eFuse rows.
To establish such protections, users need to select the read-protect/write-protect checkboxes associated with the eFuses (categorized as rows) they wish to secure.
To read-protect efuse rows, the corresponding MMRs also need to be protected using the Extended OTP array configuration in the security board configuration.
""")
        self.ext_otp_help.grid(row=0, column=4, padx=10)

        self.ext_otp_action_flags_lab = tk.Label(self.ext_otp_frm00, text="action flags :")
        self.ext_otp_action_flags_lab.grid(row=1, column=0)
        self.ext_otp_enable = tk.IntVar()
        self.ext_otp_enable_option = tk.Checkbutton(self.ext_otp_frm00, text="Enable ", variable=self.ext_otp_enable)
        self.ext_otp_enable_option.grid(row=1, column=1)

        self.ext_otp_frm01 = tk.Frame(self.ext_otp)
        self.ext_otp_frm01.pack(expand=1, fill=tk.X)

        self.ext_otp_frm01_sub0 = tk.Frame(self.ext_otp_frm01)
        self.ext_otp_frm01_sub0.grid(row=0, column=0)
        self.ext_otp_frm01_sub1 = tk.Frame(self.ext_otp_frm01)
        self.ext_otp_frm01_sub1.grid(row=0, column=1)
        self.ext_otp_err = tk.Label(self.ext_otp_frm01, text="", fg="#c00000")
        self.ext_otp_err.grid(row=1, column=0)
        
        self.ext_otp_data = []
        for i in range(0,32):
            entry = tk.Entry(self.ext_otp_frm01_sub0, width=20)
            lab = tk.Label(self.ext_otp_frm01_sub0, width=15, text="otp mmr [i]:".replace("[i]", str(i)))
            lab.grid(row=i, column=0)
            entry.grid(row=i, column=1, padx=1, pady=1)
            entry.insert("0", "00000000")
            self.ext_otp_data.append(entry)
        
        self.ext_otp_frm02 = tk.Frame(self.ext_otp)
        self.ext_otp_frm02.pack(expand=1, fill=tk.X)
        self.ext_otp_frm03 = tk.Frame(self.ext_otp)
        self.ext_otp_frm03.pack(expand=1, fill=tk.X)

        self.rp_flags = []
        self.wp_flags = []
        for r in range(0,8):
            for c in range(0,8):
                rpwpFlags = tk.LabelFrame(self.ext_otp_frm02, text="row [r]".replace("[r]", str(r*8+c)))

                wp = tk.IntVar()
                wp_option = tk.Checkbutton(rpwpFlags, text="wp", variable=wp)

                rp = tk.IntVar()
                rp_option = tk.Checkbutton(rpwpFlags, text="rp", variable=rp)

                if (r*8+c) <= 40:
                    rp_option.grid(row=1, column=0)
                    wp_option.grid(row=1, column=1)
                    rpwpFlags.grid(row=r, column=c, padx=2, pady=2)

                self.wp_flags.append((wp, wp_option))
                self.rp_flags.append((rp, rp_option))

        self.ext_otp_load_data_button = tk.Button(self.ext_otp_frm03, text="Load Data", width=20, command=self.__loadExtOtpDataFromFile)
        self.ext_otp_load_wp_flags_button = tk.Button(self.ext_otp_frm03, text="Load WP Flags", width=20, command=self.__loadExtOtpWPFlags)
        self.ext_otp_load_rp_flags_button = tk.Button(self.ext_otp_frm03, text="Load RP Flags", width=20, command=self.__loadExtOtpRPFlags)
        self.ext_otp_clear_button = tk.Button(self.ext_otp_frm03, text="Clear", width=20, command=self.__clearExtOtpData)
        #self.ext_otp_load_data_button.grid(row=10, column=0)
        #self.ext_otp_load_wp_flags_button.grid(row=10, column=1)
        #self.ext_otp_load_rp_flags_button.grid(row=10, column=2)
        self.ext_otp_clear_button.grid(row=10, column=3)
    
    def __setDefaultExtOTP(self):
        self.__clearExtOtpData()
    
    def __getExtOTPState(self):
        """
        Function to get the state of extended otp widget state.
        """
        ret_obj = {}
        ret_obj["size"] = self.ext_otp_size.get()
        ret_obj["index"] = self.ext_otp_index.get()
        ret_obj["enable"] = self.ext_otp_enable.get()
        ret_obj["ext_otp"] = []
        ret_obj["rp"] = []
        ret_obj["wp"] = []
        for i in range(0,32):
            ret_obj["ext_otp"].append(self.ext_otp_data[i].get())
        for r in range(0,8):
            for c in range(0,8):
                ret_obj["wp"].append(self.wp_flags[(r*8)+c][0].get())
                ret_obj["rp"].append(self.rp_flags[(r*8)+c][0].get())
        return ret_obj
    
    def __setExtOTPState(self, state):
        """
        Function to set the state of extended otp widget state.
        """
        self.ext_otp_size_val.set(state["size"])
        self.ext_otp_index_val.set(state["index"])
        self.ext_otp_enable.set(state["enable"])
        for i in range(0,32):
            self.ext_otp_data[i].delete(0, tk.END)
            self.ext_otp_data[i].insert("0", state["ext_otp"][i])
        for r in range(0,8):
            for c in range(0,8):
                self.wp_flags[(r*8)+c][0].set(state["wp"][(r*8)+c])
                self.rp_flags[(r*8)+c][0].set(state["rp"][(r*8)+c])
    
    def validateExtOtpValues(self, check_empty=False):
        """
        Function to validate ext otp values
        """
        err = ""

        cmd_id = self.var_cmd_ids.get()
        #otp_en = self.ext_otp_enable.get()

        if cmd_id == "one-shot" or cmd_id == "ext-otp" or cmd_id == "multi-shot":
            bits = self.ext_otp_size.get().strip()
            off = self.ext_otp_index.get().strip()

            sw = 0
            ew = 0
            hw = []
            mark = False
            if bits != "" and str_is_int(bits) and off != "" and str_is_int(off):
                bits = int(bits)
                off = int(off)

                if (off + bits) > 1024:
                    err += "Invalid size and/or offset\n"
            
                sw = int(off/32)
                ew = int((off+bits-1)/32)
                hw = list(range(sw,ew+1))

                mark = True
            else:
                if check_empty:
                    err += "Inalid Size or Index"

            for i in range(0, 32):
                val = self.ext_otp_data[i].get().strip()

                highlight = False
                if len(val) == 0:
                    if check_empty:
                        err += "Word [o] is empty\n".replace("[o]", str(i))
                    highlight = True
                elif not str_is_hex(val):
                    err += "Word [o] is not hex\n".replace("[o]", str(i))
                    highlight = True
                elif int(val, 16).bit_length() > 32:
                    err += "Word [o] value bigger than 32 bits".replace("[o]", str(i))
                    highlight = True
                
                if highlight:
                    self.ext_otp_data[i].config(bg="#F0A6A6")
                else:
                    if mark and (i in hw):
                        self.ext_otp_data[i].config(bg="#99e0cf")
                    else:
                        self.ext_otp_data[i].config(bg="#ffffff")
        
        if err != "":
            self.ext_otp_err.config(text=err)
            err += '\n'
        else:
            self.ext_otp_err.config(text="")
        
        return err
    
    def __createBottomSegment(self):
        """
        Function to create the bottom segment widget
        """
        self.bottom_segment_0 = tk.LabelFrame(self.root)
        self.generate_button = tk.Button(self.bottom_segment_0, text="Generate", width=20, bg="#CC0000", fg="white", command=self.__generateKeywrBlob)
        self.generate_button.grid(row=0, column=1, padx=5, pady=5)
    
    def __loadExtOtpDataFromFile(self):
        """
        Function to load Extended OTP data from external file
        """
        file_path = filedialog.askopenfilename(
            title="Select Ext Otp Data File"
        )
        if not file_path:
            return  # User canceled file selection

        try:    
            if file_path.endswith(".txt"):
                with open(file_path) as fl:
                    # Read all the data
                    data = fl.read()
                    data = data.split('\n')
                    for i in range(0, 32):
                        self.ext_otp_data[i].delete(0,tk.END)
                        self.ext_otp_data[i].insert("0", data[i])

            elif file_path.endswith(".bin"):
                with open(file_path, "rb") as fl:
                    # Read all the data words
                    data = fl.read(4*32)
                    for i in range(0,32):
                        integer = int.from_bytes(data[i*4, i*4+4], byteorder='little')
                        self.ext_otp_data[i].delete(0,tk.END)
                        self.ext_otp_data[i].insert("0", "{:08x}".format(integer))
        except Exception as e:
            print("Error: ", e)
    
    def __loadExtOtpWPFlags(self):
        """
        Function to load Write Protect Flags from external file
        """
        file_path = filedialog.askopenfilename(
            title="Select Ext Otp Flags File"
        )
        if not file_path:
            return  # User canceled file selection
        
        try:
            with open(file_path) as fl:
                flags = fl.read(16)
                for r in range(0,64):
                    (o,b) = ext_otp_get_octet_and_bit_idx(r)
                    #print(r, " : ", o, b)
                    val = int(flags[o*2:o*2+2], 16)
                    val = ((val >> b)&1)
                    self.wp_flags[r][0].set(val)
        except Exception as e:
            print("Error: ",e)
    
    def __loadExtOtpRPFlags(self):
        """
        Function to load Read Protect Flags from external file
        """
        file_path = filedialog.askopenfilename(
            title="Select Ext Otp Flags File"
        )
        if not file_path:
            return  # User canceled file selection

        try:
            with open(file_path) as fl:
                flags = fl.read(128)
                for r in range(0,64):
                    (o,b) = ext_otp_get_octet_and_bit_idx(r)
                    val = int(flags[o*2:o*2+2], 16)
                    val = ((val >> b)&1)
                    self.rp_flags[r][0].set(val)
        except Exception as e:
            print("Error: ",e)
    
    def __clearExtOtpData(self):
        """
        Function to clear ext otp hex editor and flags
        """
        self.ext_otp_size_val.set(1)
        self.ext_otp_index_val.set(0)

        for i in range(0,32):
            self.ext_otp_data[i].delete(0,tk.END)
            self.ext_otp_data[i].insert("0", "00000000")
        
        for i in range(0, 64):
            self.rp_flags[i][0].set(0)
            self.wp_flags[i][0].set(0)
    
    #####################################################
    # FUNCTIONS TO CREATE AND INTERACT WITH WIDGETS - END
    #####################################################





    #################################################
    # FUNCTIONS TO MANAGE THE GUI IN REALTIME - START
    #################################################

    def __hideKeywrModeWidgets(self):
        """
        Function to hide keywriter mode selection menu
        """
        self.keywriter_mode_cbox0.pack_forget()
        self.keywriter_mode_cbox1.pack_forget()
    
    def __hideAllFieldWidgets(self):
        """
        Fuction to hide all keywriter field widgets
        """
        self.mpkh.pack_forget()
        self.smpkh_segment_frm.pack_forget()
        self.bmpkh_segment_frm.pack_forget()
        self.mpkh_flag = False
        self.key_cnt.pack_forget()
        self.key_rev.pack_forget()
        self.sbl_swrev.pack_forget()
        self.sysfw_swrev.pack_forget()
        self.brdcfg_swrev.pack_forget()
        self.msv.pack_forget()
        self.jtag_disable.pack_forget()
        self.boot_mode.pack_forget()
        self.ext_otp.pack_forget()
        self.bottom_segment_0.pack_forget()
    
    def __hideKeywrLiteHeaderWidget(self):
        """
        Function to hide keywriter lite header widget
        """
        self.top_segment_1.pack_forget()

    def __showWidgets(self, widget):
        """
        Function to show specific widgets
        """

        if widget == "keywr-hdr":
            self.top_segment_1.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "smpkh":
            self.smpkh_segment_frm.pack(expand=1, fill=tk.X)
            self.mpkh.pack(expand=1, fill=tk.X, padx=5)
            self.mpkh_flag = True
        elif widget == "bmpkh":
            self.bmpkh_segment_frm.pack(expand=1, fill=tk.X)
            self.mpkh.pack(expand=1, fill=tk.X, padx=5)
            self.mpkh_flag = True
        elif widget == "key-cnt":
            self.key_cnt.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "key-rev":
            self.key_rev.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "sbl-swrev":
            self.sbl_swrev.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "sysfw-swrev":
            self.sysfw_swrev.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "brdcfg-swrev":
            self.brdcfg_swrev.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "msv":
            self.msv.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "jtag-disable":
            self.jtag_disable.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "boot-mode":
            self.boot_mode.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "ext-otp":
            self.ext_otp.pack(expand=1, fill=tk.X, padx=5)
        elif widget == "bottom0":
            self.bottom_segment_0.pack(expand=1, fill=tk.X, padx=5)
    
    def __revealWidgets(self):
        """
        Function to reveal appropriate widgets
        """
        device = self.var_device.get()
        keywr_mode = self.keywriter_mode_disp.get()

        if keywr_mode == 0:
            supported_fields = soc_data[device]["keywriter"]["supported_fields"]
            # Display all supported fields
            for field in supported_fields:
                self.__showWidgets(field)
        else:
            version = self.var_keywr_lite_ver.get()
            cmd_id = self.var_cmd_ids.get()
            supported_fields = soc_data[device]["keywriter-lite"][version]["supported_fields"]

            self.__showWidgets("keywr-hdr")
            if cmd_id == "one-shot" or cmd_id == "multi-shot":
                for field in supported_fields:
                    self.__showWidgets(field)
            else:
                self.__showWidgets(cmd_id)
        self.__showWidgets("bottom0")
    
    def __updateKeywrABI(self, major, minor):
        """
        Function to update abi version in the widget
        """
        self.abi_maj_val.set(major)
        self.abi_min_val.set(minor)

    def __updateKeywrLiteVersions(self, keywr_lite_versions):
        """
        Function to update keywriter lite version in the menu
        """
        self.var_keywr_lite_ver.set(keywr_lite_versions[0])
        self.keywr_lite_menu["menu"].delete(0, "end")
        for ver in keywr_lite_versions:
            self.keywr_lite_menu["menu"].add_command(label=ver, command=tk._setit(self.var_keywr_lite_ver, ver, self.__updateGUIWhenKeywrLiteVerChanges))

    def __updateCommandIDs(self, cmd_ids):
        """
        Function to update command ids in the command id menu
        """
        self.var_cmd_ids.set(cmd_ids[0])
        self.cmd_ids_menu["menu"].delete(0, "end")
        for cmd_id in cmd_ids:
            self.cmd_ids_menu["menu"].add_command(label=cmd_id, command=tk._setit(self.var_cmd_ids, cmd_id, self.__updateGUIWhenCmdIdChanges))

    def __updateKeywrHeaderFromDevice(self):
        """
        Function to update keywriter lite header widget based on the currently selected device.
        """
        if self.keywriter_mode_disp.get() == 1:
            # Create header from soc-defaultsfT
            device = self.var_device.get()
            keywr_lite_versions = soc_data[device]["keywriter-lite"]["versions"]
            keywr_lite_default_version = soc_data[device]["keywriter-lite"]["default_version"]
            command_ids = ['one-shot', 'multi-shot'] + soc_data[device]["keywriter-lite"][keywr_lite_default_version]["supported_fields"]
            abi_major = soc_data[device]["keywriter-lite"][keywr_lite_default_version]["abi-major"]
            abi_minor = soc_data[device]["keywriter-lite"][keywr_lite_default_version]["abi-minor"]
            self.__updateKeywrLiteVersions(keywr_lite_versions)
            self.__updateCommandIDs(command_ids)
            self.__updateKeywrABI(abi_major, abi_minor)
    
    def __updateKeywrModeFromDevice(self):
        """
        Function to update list of suppirted keywriter modes supported by currently selected device.
        """
        device = self.var_device.get()

        if "keywriter" in soc_data[device]:
            self.keywriter_mode_cbox0.pack(expand=1, padx=5, pady=5)
            self.keywriter_mode_cbox0.select()
        
        if "keywriter-lite" in soc_data[device]:
            self.keywriter_mode_cbox1.pack(expand=1, padx=5, pady=5)
            self.keywriter_mode_cbox1.select()
    
    def __updateGUIWhenDeviceChanges(self, dev):
        """
        Function to update GUI whenever device name changes.
        """
        self.__hideKeywrModeWidgets()
        self.__hideAllFieldWidgets()
        self.__hideKeywrLiteHeaderWidget()
        self.__updateKeywrModeFromDevice()
        self.__updateKeywrHeaderFromDevice()
        self.__revealWidgets()
    
    def __updateGUIWhenKeywrModeChanges(self):
        """
        Fuction to update GUI whenever keywriter mode changes.
        """
        #mode = self.keywriter_mode_disp.get()
        self.__hideAllFieldWidgets()
        self.__hideKeywrLiteHeaderWidget()
        self.__updateKeywrHeaderFromDevice()
        self.__revealWidgets()
    
    def __updateGUIWhenKeywrLiteVerChanges(self, keywr_lite_version):
        """
        Function to update GUI whenever keywriter lite version changes.
        """
        device = self.var_device.get()

        command_ids = ['one-shot', 'multi-shot'] + soc_data[device]["keywriter-lite"][keywr_lite_version]["supported_fields"]
        abi_major = soc_data[device]["keywriter-lite"][keywr_lite_version]["abi-major"]
        abi_minor = soc_data[device]["keywriter-lite"][keywr_lite_version]["abi-minor"]

        self.__hideAllFieldWidgets()
        
        self.__updateCommandIDs(command_ids)
        self.__updateKeywrABI(abi_major, abi_minor)

        self.__revealWidgets()
    
    def __enableAndLockAllEnableBoxes(self):
        """
        Function to enable and lock all enable boxes across all field widgets.
        """
        self.smpkh_enable.set(1)
        self.smpkh_enable_option.config(state=tk.DISABLED)

        self.bmpkh_enable.set(1)
        self.bmpkh_enable_option.config(state=tk.DISABLED)

        self.key_cnt_enable.set(1)
        self.key_cnt_enable_option.config(state=tk.DISABLED)

        self.key_rev_enable.set(1)
        self.key_rev_enable_option.config(state=tk.DISABLED)

        self.sbl_swrev_enable.set(1)
        self.sbl_swrev_enable_option.config(state=tk.DISABLED)

        self.sysfw_swrev_enable.set(1)
        self.sysfw_swrev_enable_option.config(state=tk.DISABLED)

        self.brdcfg_swrev_enable.set(1)
        self.brdcfg_swrev_enable_option.config(state=tk.DISABLED)

        self.msv_enable.set(1)
        self.msv_enable_option.config(state=tk.DISABLED)

        self.jtag_disable_enable.set(1)
        self.jtag_disable_enable_option.config(state=tk.DISABLED)

        self.boot_mode_enable.set(1)
        self.boot_mode_enable_option.config(state=tk.DISABLED)

        self.ext_otp_enable.set(1)
        self.ext_otp_enable_option.config(state=tk.DISABLED)
    
    def __unlockAllEnableBoxes(self):
        """
        Function to unlock all enable checkboxes across all field widgets.
        """
        self.smpkh_enable_option.config(state=tk.NORMAL)
        self.bmpkh_enable_option.config(state=tk.NORMAL)
        self.key_cnt_enable_option.config(state=tk.NORMAL)
        self.key_rev_enable_option.config(state=tk.NORMAL)
        self.sbl_swrev_enable_option.config(state=tk.NORMAL)
        self.sysfw_swrev_enable_option.config(state=tk.NORMAL)
        self.brdcfg_swrev_enable_option.config(state=tk.NORMAL)
        self.msv_enable_option.config(state=tk.NORMAL)
        self.jtag_disable_enable_option.config(state=tk.NORMAL)
        self.boot_mode_enable_option.config(state=tk.NORMAL)
        self.ext_otp_enable_option.config(state=tk.NORMAL)

    
    def __enableAndUnlockAllEnableBoxes(self):
        """
        Function to enable and unlock all enable checkboxes across all field widgets.
        """
        self.smpkh_enable.set(1)
        self.smpkh_enable_option.config(state=tk.NORMAL)

        self.bmpkh_enable.set(1)
        self.bmpkh_enable_option.config(state=tk.NORMAL)

        self.key_cnt_enable.set(1)
        self.key_cnt_enable_option.config(state=tk.NORMAL)

        self.key_rev_enable.set(1)
        self.key_rev_enable_option.config(state=tk.NORMAL)

        self.sbl_swrev_enable.set(1)
        self.sbl_swrev_enable_option.config(state=tk.NORMAL)

        self.sysfw_swrev_enable.set(1)
        self.sysfw_swrev_enable_option.config(state=tk.NORMAL)

        self.brdcfg_swrev_enable.set(1)
        self.brdcfg_swrev_enable_option.config(state=tk.NORMAL)

        self.msv_enable.set(1)
        self.msv_enable_option.config(state=tk.NORMAL)

        self.jtag_disable_enable.set(1)
        self.jtag_disable_enable_option.config(state=tk.NORMAL)

        self.boot_mode_enable.set(1)
        self.boot_mode_enable_option.config(state=tk.NORMAL)

        self.ext_otp_enable.set(1)
        self.ext_otp_enable_option.config(state=tk.NORMAL)

    def __updateGUIWhenCmdIdChanges(self, cmd_id):
        """
        Function to update the gui whenever commmand id changes.
        """
        device = self.var_device.get()
        version = self.var_keywr_lite_ver.get()
        supported_fields = soc_data[device]["keywriter-lite"][version]["supported_fields"]
        
        self.__hideAllFieldWidgets()

        if cmd_id == "multi-shot":
            self.__enableAndUnlockAllEnableBoxes()
        else:
            self.__enableAndLockAllEnableBoxes()

        if cmd_id == "one-shot" or cmd_id == "multi-shot":
            for field in supported_fields:
                self.__showWidgets(field)
        else:
            self.__showWidgets(cmd_id)
        
        self.__showWidgets("bottom0")

    def __updateGUIUponStateImport(self, cmd_id):
        """
        Function to update the gui whenever commmand id changes.
        """
        device = self.var_device.get()
        version = self.var_keywr_lite_ver.get()
        supported_fields = soc_data[device]["keywriter-lite"][version]["supported_fields"]
        
        self.__hideAllFieldWidgets()

        if cmd_id == "multi-shot":
            self.__unlockAllEnableBoxes()
        else:
            self.__enableAndLockAllEnableBoxes()

        if cmd_id == "one-shot" or cmd_id == "multi-shot":
            for field in supported_fields:
                self.__showWidgets(field)
        else:
            self.__showWidgets(cmd_id)
        
        self.__showWidgets("bottom0")
    
    ###############################################
    # FUNCTIONS TO MANAGE THE GUI IN REALTIME - END
    ###############################################
    




    ###############################################
    # FUNCTIONS TO GENERATE KEYWRITER BLOB - START
    ###############################################

    def __genKeywrLiteHeaderBlob(self, size):
        """
        Function to generate the keywriter lite header blob to constitute the keywriter blob.
        """
        abi_maj = self.abi_maj_val.get()
        abi_min = self.abi_min_val.get()
        cmd_id = KEYWR_LITE_CMD_TO_CMD_ID_MAP[self.var_cmd_ids.get()]
        keywr_lite_hdr = keywrlite_header(size=size, abi_maj=abi_maj, abi_min=abi_min, cmd_id=cmd_id)

        self.declarations = keywr_lite_hdr.getStructDeclaration() + self.declarations
        self.blob_declarations = "    struct " + keywr_lite_hdr.getStructName() + " header;\n" + self.blob_declarations
        self.definitions = "    .header =" + keywr_lite_hdr.getObject() + ",\n" + self.definitions

        return keywr_lite_hdr.tobin()
    
    def __genMPKOptsBlob(self):
        """
        Function to generate the mpk options blob to constitute the keywriter blob.
        """
        mpk_opts = keywrlite_mpk_opts(self.mpk_opts_box.get().strip())
        if self.smpkh_enable.get()==1 or self.bmpkh_enable.get()==1:
            mpk_opts.action_flags.enable(True)
        
        self.declarations += mpk_opts.getStructDeclaration()
        self.blob_declarations += "    struct " + mpk_opts.getStructName() + " mpkopts;\n"
        self.definitions += "    .mpkopts =" + mpk_opts.getObject() + ",\n"
        
        return mpk_opts.tobin()

    def __genSMPKHBlob(self):
        """
        Function to generate the smpkh blob to constitute the keywriter blob.
        """
        smpkh = keywrlite_mpkh(True)

        # Set action flags
        smpkh.action_flags.enable((bool)(self.smpkh_enable.get()))
        smpkh.action_flags.override((bool)(self.smpkh_override.get()))
        smpkh.action_flags.read_protect((bool)(self.smpkh_read_protect.get()))
        smpkh.action_flags.write_protect((bool)(self.smpkh_write_protect.get()))

        mpkh = self.smpkh_box.get().strip()
        for i in range(0,128,2):
            octet = keywrlite_type_uint8_t(mpkh[i:i+2])
            smpkh.mpkh.add(octet)
        
        if not ("struct mpkh " in self.declarations):
            self.declarations += smpkh.getStructDeclaration()
        self.blob_declarations += "    struct " + smpkh.getStructName() + " smpkh;\n"
        self.definitions += "    .smpkh =" + smpkh.getObject() + ",\n"

        return smpkh.tobin()
    
    def __genBMPKHBlob(self):
        """
        Function to generate the bmpkh field blob to constitute the keywriter blob.
        """
        bmpkh = keywrlite_mpkh(False)

        # Set action flags
        bmpkh.action_flags.enable((bool)(self.bmpkh_enable.get()))
        bmpkh.action_flags.override((bool)(self.bmpkh_override.get()))
        bmpkh.action_flags.read_protect((bool)(self.bmpkh_read_protect.get()))
        bmpkh.action_flags.write_protect((bool)(self.bmpkh_write_protect.get()))

        mpkh = self.bmpkh_box.get().strip()
        for i in range(0,128,2):
            octet = keywrlite_type_uint8_t(mpkh[i:i+2])
            bmpkh.mpkh.add(octet)
        
        if not ("struct mpkh " in self.declarations):
            self.declarations += bmpkh.getStructDeclaration()
        self.blob_declarations += "    struct " + bmpkh.getStructName() + " bmpkh;\n"
        self.definitions += "    .bmpkh =" + bmpkh.getObject() + ",\n"

        return bmpkh.tobin()
    
    def __genKeyCntBlob(self):
        """
        Function to generate the key count blob to constitute the keywriter blob.
        """
        val = self.key_cnt_menu.get()
        key_cnt = keywrlite_key_cnt(int(val))

        # Set action flags
        key_cnt.action_flags.enable((bool)(self.key_cnt_enable.get()))
        key_cnt.action_flags.override((bool)(self.key_cnt_override.get()))
        key_cnt.action_flags.read_protect((bool)(self.key_cnt_read_protect.get()))
        key_cnt.action_flags.write_protect((bool)(self.key_cnt_write_protect.get()))

        self.declarations += key_cnt.getStructDeclaration()
        self.blob_declarations += "    struct " + key_cnt.getStructName() + " keycnt;\n"
        self.definitions += "    .keycnt =" + key_cnt.getObject() + ",\n"

        return key_cnt.tobin()
    
    def __genKeyRevBlob(self):
        """
        Function to generate the key revision blob to constitute the keywriter blob.
        """
        val = self.key_rev_menu.get()
        key_rev = keywrlite_key_rev(int(val))

        # Set action flags
        key_rev.action_flags.enable((bool)(self.key_rev_enable.get()))
        key_rev.action_flags.override((bool)(self.key_rev_override.get()))
        key_rev.action_flags.read_protect((bool)(self.key_rev_read_protect.get()))
        key_rev.action_flags.write_protect((bool)(self.key_rev_write_protect.get()))

        self.declarations += key_rev.getStructDeclaration()
        self.blob_declarations += "    struct " + key_rev.getStructName() + " keyrev;\n"
        self.definitions += "    .keyrev =" + key_rev.getObject() + ",\n"

        return key_rev.tobin()
    
    def __genSBLSWRevBlob(self):
        """
        Function to generate a sbl swrev blob to constitute the keywriter blob.
        """
        val = self.sbl_swrev_menu.get()
        sbl_swrev = keywrlite_sbl_swrev(int(val))

        # Set action flags
        sbl_swrev.action_flags.enable((bool)(self.sbl_swrev_enable.get()))
        sbl_swrev.action_flags.override((bool)(self.sbl_swrev_override.get()))
        sbl_swrev.action_flags.read_protect((bool)(self.sbl_swrev_read_protect.get()))
        sbl_swrev.action_flags.write_protect((bool)(self.sbl_swrev_write_protect.get()))

        self.declarations += sbl_swrev.getStructDeclaration()
        self.blob_declarations += "    struct " + sbl_swrev.getStructName() + " sblswrev;\n"
        self.definitions += "    .sblswrev =" + sbl_swrev.getObject() + ",\n"

        return sbl_swrev.tobin()
    
    def __genSYSFWSWRevBlob(self):
        """
        Function to generate a sysfw swrev blob to constitute the keywriter blob.
        """
        val = self.sysfw_swrev_menu.get()
        sysfw_swrev = keywrlite_sysfw_swrev(int(val))

        # Set action flags
        sysfw_swrev.action_flags.enable((bool)(self.sysfw_swrev_enable.get()))
        sysfw_swrev.action_flags.override((bool)(self.sysfw_swrev_override.get()))
        sysfw_swrev.action_flags.read_protect((bool)(self.sysfw_swrev_read_protect.get()))
        sysfw_swrev.action_flags.write_protect((bool)(self.sysfw_swrev_write_protect.get()))

        self.declarations += sysfw_swrev.getStructDeclaration()
        self.blob_declarations += "    struct " + sysfw_swrev.getStructName() + " sysfwswrev;\n"
        self.definitions += "    .sysfwswrev =" + sysfw_swrev.getObject() + ",\n"

        return sysfw_swrev.tobin()

    def __genBRDCFGSWRevBlob(self):
        """
        Function to generate a board-config swrev blob to constitute the keywriter blob.
        """
        val = self.brdcfg_swrev_menu.get()
        brdcfg_swrev = keywrlite_brdcfg_swrev(int(val))

        # Set action flags
        brdcfg_swrev.action_flags.enable((bool)(self.brdcfg_swrev_enable.get()))
        brdcfg_swrev.action_flags.override((bool)(self.brdcfg_swrev_override.get()))
        brdcfg_swrev.action_flags.read_protect((bool)(self.brdcfg_swrev_read_protect.get()))
        brdcfg_swrev.action_flags.write_protect((bool)(self.brdcfg_swrev_write_protect.get()))

        self.declarations += brdcfg_swrev.getStructDeclaration()
        self.blob_declarations += "    struct " + brdcfg_swrev.getStructName() + " brdcfgswrev;\n"
        self.definitions += "    .brdcfgswrev =" + brdcfg_swrev.getObject() + ",\n"

        return brdcfg_swrev.tobin()
    
    def __genMSVBlob(self):
        """
        Function to generate a msv blob to constitute the keywriter blob.
        """
        val = self.msv_menu.get().strip()
        msv = keywrlite_msv(val)

        # Set action flags
        msv.action_flags.enable(bool(self.msv_enable.get()))
        msv.action_flags.override(bool(self.msv_override.get()))
        msv.action_flags.read_protect(bool(self.msv_read_protect.get()))
        msv.action_flags.write_protect(bool(self.msv_write_protect.get()))

        self.declarations += msv.getStructDeclaration()
        self.blob_declarations += "    struct " + msv.getStructName() + " msv;\n"
        self.definitions += "    .msv =" + msv.getObject() + ",\n"

        return msv.tobin()

    def __genJTAGDisableBlob(self):
        """
        Function to generate a jtag disable blob to constitute the keywriter blob.
        """
        jtag_disable = keywrlite_jtag_unlock_disable(bool(self.jtag_disable_enable.get()))

        # Set action flags
        jtag_disable.action_flags.enable(bool(self.jtag_disable_enable.get()))
        jtag_disable.action_flags.override(bool(self.jtag_disable_override.get()))
        jtag_disable.action_flags.read_protect(bool(self.jtag_disable_read_protect.get()))
        jtag_disable.action_flags.write_protect(bool(self.jtag_disable_write_protect.get()))

        self.declarations += jtag_disable.getStructDeclaration()
        self.blob_declarations += "    struct " + jtag_disable.getStructName() + " jtagdisable;\n"
        self.definitions += "    .jtagdisable =" + jtag_disable.getObject() + ",\n"

        return jtag_disable.tobin()
    
    def __genBootModeBlob(self):
        """
        Function to generate a boot mode blob to constitute the keywriter blob.
        """
        fuse_id = self.fuse_id_menu.get()
        boot_mode_val = self.boot_mode_menu.get().strip()

        boot_mode = keywrlite_boot_mode(fuse_id, boot_mode_val)

        # Set action flags
        boot_mode.action_flags.enable(bool(self.boot_mode_enable.get()))
        boot_mode.action_flags.override(bool(self.boot_mode_override.get()))
        boot_mode.action_flags.read_protect(bool(self.boot_mode_read_protect.get()))
        boot_mode.action_flags.write_protect(bool(self.boot_mode_write_protect.get()))

        self.declarations += boot_mode.getStructDeclaration()
        self.blob_declarations += "    struct " + boot_mode.getStructName() + " bootmode;\n"
        self.definitions += "    .bootmode =" + boot_mode.getObject() + ",\n"

        return boot_mode.tobin()
    
    def __genExtOtpBlob(self):
        """
        Function to generate a extended otp blob to constitute the keywriter blob.
        """

        ext_otp = keywrlite_ext_otp()

        # Set action flags
        ext_otp.action_flags.enable(bool(self.ext_otp_enable.get()))

        ext_otp.ext_otp_size.VAL = int(self.ext_otp_size.get().strip())
        ext_otp.ext_otp_index.VAL = int(self.ext_otp_index.get().strip())

        wpfg = [0] * 8
        for i in range(0,64):
            if self.wp_flags[i][0].get() == 1:
                (o,r) = ext_otp_get_octet_and_bit_idx(i)
                wpfg[o] |= (1<<r)

        rpfg = [0] * 8
        for i in range(0,64):
            if self.rp_flags[i][0].get() == 1:
                (o,r) = ext_otp_get_octet_and_bit_idx(i)
                rpfg[o] |= (1<<r)

        for i in range(0,8):
            ext_otp.ext_otp_rpwp.add(keywrlite_type_uint8_t(wpfg[i]))
        for i in range(0,8):
            ext_otp.ext_otp_rpwp.add(keywrlite_type_uint8_t(rpfg[i]))

        for i in range(0,32):
            octet = self.ext_otp_data[i].get().strip()
            ext_otp.ext_otp.add(keywrlite_type_uint32_t(octet))
        
        self.declarations += ext_otp.getStructDeclaration()
        self.blob_declarations += "    struct " + ext_otp.getStructName() + " extotp;\n"
        self.definitions += "    .extotp =" + ext_otp.getObject() + ",\n"
        
        return ext_otp.tobin()

    def __getFieldBlob(self, id):
        """
        Function to generate a field blob to constitute the keywriter blob.
        """
        retbin = b''
        if id == "mpkopts":
            retbin += self.__genMPKOptsBlob()
        elif id == "smpkh":
            retbin += self.__genSMPKHBlob()
        elif id == "bmpkh":
            retbin += self.__genBMPKHBlob()
        elif id == "key-cnt":
            retbin += self.__genKeyCntBlob()
        elif id == "key-rev":
            retbin += self.__genKeyRevBlob()
        elif id == "sbl-swrev":
            retbin += self.__genSBLSWRevBlob()
        elif id == "sysfw-swrev":
            retbin += self.__genSYSFWSWRevBlob()
        elif id == "brdcfg-swrev":
            retbin += self.__genBRDCFGSWRevBlob()
        elif id == "msv":
            retbin += self.__genMSVBlob()
        elif id == "jtag-disable":
            retbin += self.__genJTAGDisableBlob()
        elif id == "boot-mode":
            retbin += self.__genBootModeBlob()
        elif id == "ext-otp":
            retbin += self.__genExtOtpBlob()

        return retbin
    
    def __isFieldEnabled(self, id):
        """
        Function to check if a field is enabled.
        """
        ret = 0
        if id == "mpkopts":
            if self.smpkh_enable.get() == 1 or self.bmpkh_enable.get() == 1:
                ret = 1
        elif id == "smpkh":
            ret = self.smpkh_enable.get()
        elif id == "bmpkh":
            ret = self.bmpkh_enable.get()
        elif id == "key-cnt":
            ret = self.key_cnt_enable.get()
        elif id == "key-rev":
            ret = self.key_rev_enable.get()
        elif id == "sbl-swrev":
            ret = self.sbl_swrev_enable.get()
        elif id == "sysfw-swrev":
            ret = self.sysfw_swrev_enable.get()
        elif id == "brdcfg-swrev":
            ret = self.brdcfg_swrev_enable.get()
        elif id == "msv":
            ret = self.msv_enable.get()
        elif id == "jtag-disable":
            ret = self.jtag_disable_enable.get()
        elif id == "boot-mode":
            ret = self.boot_mode_enable.get()
        elif id == "ext-otp":
            ret = self.ext_otp_enable.get()
        return ret
    
    def __setFieldDefault(self, id):
        """
        Function to set default values in the different field widgets.
        """
        if id == "mpkopts":
            self.__setDefaultMpkOpts()
        elif id == "smpkh":
            self.__setDefaultSMPKH()
        elif id == "bmpkh":
            self.__setDefaultBMPKH()
        elif id == "key-cnt":
            self.__setDefaultKeyCnt()
        elif id == "key-rev":
            self.__setDefaultKeyRev()
        elif id == "sbl-swrev":
            self.__setDefaultSBLSWRev()
        elif id == "sysfw-swrev":
            self.__setDefaultSYSFWSWRev()
        elif id == "brdcfg-swrev":
            self.__setDefaultBRDCFGSWRev()
        elif id == "msv":
            self.__setDefaultMSV()
        elif id == "jtag-disable":
            pass
        elif id == "boot-mode":
            self.__setDefaultBootMode()
        elif id == "ext-otp":
            self.__setDefaultExtOTP()
        
    def __validateField(self, id, check_empty=False):
        """
        Function to validate different fields supported by the tool.
        """
        err = ""
        if id == "mpkopts" or id == "smpkh" or id == "bmpkh":
            err += self.validateMPKHValues(check_empty)
        elif id == "key-cnt":
            err = self.validateKeyCntValue(check_empty)
        elif id == "key-rev":
            err = self.validateKeyRevValue(check_empty)
        elif id == "sbl-swrev":
            err = self.validateSBLSWRevValue(check_empty)
        elif id == "sysfw-swrev":
            err = self.validateSYSFWSWRevValue(check_empty)
        elif id == "brdcfg-swrev":
            err = self.validateBRDCFGSWRevValue(check_empty)
        elif id == "msv":
            err = self.validateMSVValue(check_empty)
        elif id == "jtag-disable":
            err = self.validateJTAGDisableValue(check_empty)
        elif id == "boot-mode":
            err = self.validateBootModeValues(check_empty)
        elif id == "ext-otp":
            err = self.validateExtOtpValues(check_empty)
        return err
    
    def __generateKeywrBlob(self):
        """
        This function creates keywriter output blob and a blob C source file.
        """

        device = self.var_device.get()
        keywr_mode = self.keywriter_mode_disp.get()

        if keywr_mode == 1:
            self.declarations = ""
            self.blob_declarations = ""
            self.definitions = ""

            keywrlite_ver = self.var_keywr_lite_ver.get()
            cmd_id = self.var_cmd_ids.get()
            blob_struct = soc_data[device]["keywriter-lite"][keywrlite_ver]["blob_struct"]

            # Fill in default values for dissabled fields in multishot mode
            if cmd_id == "multi-shot":
                for field in blob_struct:
                    if not field.startswith("u8_"):
                        if self.__isFieldEnabled(field) == 0:
                            self.__setFieldDefault(field)

            # Initialize payload variable
            keywrlite_payload = b''
            if cmd_id == "one-shot" or cmd_id == "multi-shot":
                for field in blob_struct:
                    if field.startswith("u8_"):
                        keywrlite_payload += b''
                    else:
                        err = self.__validateField(field, True)
                        if err != "":
                            messagebox.showerror("Error", err)
                            return
                        else:
                            keywrlite_payload += self.__getFieldBlob(field)
            elif cmd_id == "smpkh" or cmd_id == "bmpkh":
                err = self.__validateField(cmd_id, True)
                if err != "":
                    messagebox.showerror("Error", err)
                    return
                keywrlite_payload += self.__getFieldBlob("mpkopts") + self.__getFieldBlob(cmd_id)
            else:
                err = self.__validateField(cmd_id, True)
                if err != "":
                    messagebox.showerror("Error", err)
                    return
                keywrlite_payload += self.__getFieldBlob(cmd_id)
            
            keywrlite_payload_size = len(keywrlite_payload)
            keywrlite_header = self.__genKeywrLiteHeaderBlob(keywrlite_payload_size)
            keywrlite_header_payload = keywrlite_header + keywrlite_payload
            
            chksum = hash_blob(keywrlite_header_payload)
            chksum_obj = keywrlite_checksum()
            for i in range(0,128,2):
                chksumByt = chksum[i:i+2]
                chksum_obj.hash.add(keywrlite_type_uint8_t(chksumByt))
            keywrlite_chksum = chksum_obj.tobin()

            uboot_header_obj = keywrlite_uboot_header()
            keywrlite_ub_header = uboot_header_obj.tobin()

            print(keywrlite_ub_header)
            print(keywrlite_header_payload)
            print(keywrlite_chksum)

            self.declarations = uboot_header_obj.getStructDeclaration() + self.declarations
            self.blob_declarations = "    struct " + uboot_header_obj.getStructName() + " ubheader;\n" + self.blob_declarations
            self.definitions = "    .ubheader =" + uboot_header_obj.getObject() + ",\n" + self.definitions

            self.declarations += chksum_obj.getStructDeclaration()
            self.blob_declarations += "    struct " + chksum_obj.getStructName() + " chksum;\n"
            self.definitions += "    .chksum =" + chksum_obj.getObject() + ",\n"

            typedefs = """
// Uncomment and modify the following definitions as per the compiler used
// typedef char uint8_t;
// typedef unsigned short uint16_t;
// typedef unsigned int uint32_t;
// typedef unsigned long uint64_t;
"""
            self.declarations = typedefs + self.declarations

            self.blob_declarations = "struct keywrlite_blob {\n" + self.blob_declarations + "}__attribute__((packed));\n"
            self.definitions = "struct keywrlite_blob blob = {\n" + self.definitions + "\n};"

            folder_path= filedialog.askdirectory(title="Select Output Folder")
            if folder_path:
                with open(folder_path+"/keywrlite.bin", "wb") as fl:
                    fl.write(keywrlite_ub_header + keywrlite_header_payload + keywrlite_chksum)

                with open(folder_path+"/keywrlite.c", "w") as fl:
                    fl.write(self.declarations + "\n" + self.blob_declarations + "\n" + self.definitions)
            else:
                pass
        else:
            # Keywriter mode not supported yet
            pass
    
    #############################################
    # FUNCTIONS TO GENERATE KEYWRITER BLOB - END
    #############################################
    




    #####################################
    # FUNCTIONS TO SAVE / RESTORE - START
    #####################################

    def __saveToolState(self):
        """
        Function to save tool state
        """
        progress = {}
        
        def getFieldProgress(field):
            ret_obj = None
            if field == "mpkopts":
                ret_obj = self.__getMPKOptsState()
            if field == "smpkh":
                ret_obj = self.__getMPKHState(True)
            elif field == "bmpkh":
                ret_obj = self.__getMPKHState(False)
            elif field == "key-cnt":
                ret_obj = self.__getKeyCntState()
            elif field == "key-rev":
                ret_obj = self.__getKeyRevState()
            elif field == "sbl-swrev":
                ret_obj = self.__getSBLSWRevState()
            elif field == "sysfw-swrev":
                ret_obj = self.__getSYSFWSWRevState()
            elif field == "brdcfg-swrev":
                ret_obj = self.__getBRDCFGSWRevState()
            elif field == "msv":
                ret_obj = self.__getMSVState()
            elif field == "jtag-disable":
                ret_obj = self.__getJTAGDisableState()
            elif field == "boot-mode":
                ret_obj = self.__getBootModeState()
            elif field == "ext-otp":
                ret_obj = self.__getExtOTPState()
            return ret_obj
        
        progress["device"] = self.var_device.get()
        progress["keywr_mode"] = self.keywriter_mode_disp.get()

        if progress["keywr_mode"] == 1:
            # Keywriter lite mode
            progress["version"] = self.var_keywr_lite_ver.get()
            progress["abi_major"] = self.abi_maj_menu.get()
            progress["abi_minor"] = self.abi_min_menu.get()
            progress["cmd_id"] = self.var_cmd_ids.get()
            progress["fields"] = {}

            blob_struct = soc_data[progress["device"]]["keywriter-lite"][progress["version"]]["blob_struct"]

            if progress["cmd_id"] == "one-shot" or progress["cmd_id"] == "multi-shot":
                for field in blob_struct:
                    if not field.startswith("u8_"):
                        progress["fields"][field] = getFieldProgress(field)
            elif progress["cmd_id"] == "smpkh" or progress["cmd_id"] == "bmpkh":
                progress["fields"]["mpkopts"] = getFieldProgress("mpkopts")
                progress["fields"][progress["cmd_id"]] = getFieldProgress(progress["cmd_id"])
            else:
                progress["fields"][progress["cmd_id"]] = getFieldProgress(progress["cmd_id"])
        else:
            # Keywriter mode
            pass

        out_file_path= filedialog.asksaveasfilename(title="Save File As", defaultextension=".json", filetypes=[("JSON Files","*.json")])
        if out_file_path:
            with open(out_file_path, "w") as fl:
                fl.write(json.dumps(progress, indent=4))
            messagebox.showinfo("", "Progress Saved")
        else:
            pass

    def __restoreToolState(self):
        """
        Function to restore tool state
        """
        
        def setFieldProgress(field, state):
            if field == "mpkopts":
                self.__setMPKOptsState(state)
            if field == "smpkh":
                self.__setMPKHState(state, True)
            elif field == "bmpkh":
                self.__setMPKHState(state, False)
            elif field == "key-cnt":
                self.__setKeyCntState(state)
            elif field == "key-rev":
                self.__setKeyRevState(state)
            elif field == "sbl-swrev":
                self.__setSBLSWRevState(state)
            elif field == "sysfw-swrev":
                self.__setSYSFWSWRevState(state)
            elif field == "brdcfg-swrev":
                self.__setBRDCFGSWRevState(state)
            elif field == "msv":
                self.__setMSVState(state)
            elif field == "jtag-disable":
                self.__setJTAGDisableState(state)
            elif field == "boot-mode":
                self.__setBootModeState(state)
            elif field == "ext-otp":
                self.__setExtOTPState(state)

        try:
            file_path = filedialog.askopenfilename(title="Select State File", initialdir="./", filetypes=[("JSON Files", "*.json")])
            if file_path:
                with open(file_path, "r") as fl:
                    tool_state = json.loads(fl.read())
            else:
                pass
        except:
            messagebox.showerror("", "Data file not found")
            return
        
        try:
            self.var_device.set(tool_state["device"])
            self.__updateGUIWhenDeviceChanges(tool_state["device"])
            self.keywriter_mode_disp.set(tool_state["keywr_mode"])
            self.__updateGUIWhenKeywrModeChanges()

            if tool_state["keywr_mode"] == 1:
                # Keywriter lite mode
                self.var_keywr_lite_ver.set(tool_state["version"])
                self.__updateGUIWhenKeywrLiteVerChanges(tool_state["version"])
                self.abi_maj_val.set(tool_state["abi_major"])
                self.abi_min_val.set(tool_state["abi_minor"])
                self.var_cmd_ids.set(tool_state["cmd_id"])
                self.__hideAllFieldWidgets()

                blob_struct = soc_data[tool_state["device"]]["keywriter-lite"][tool_state["version"]]["blob_struct"]

                if tool_state["cmd_id"] == "one-shot" or tool_state["cmd_id"] == "multi-shot":
                    fields = list(tool_state["fields"].keys())
                    for field in fields:
                        setFieldProgress(field, tool_state["fields"][field])
                elif tool_state["cmd_id"] == "smpkh" or tool_state["cmd_id"] == "bmpkh":
                    setFieldProgress("mpkopts", tool_state["fields"]["mpkopts"])
                    setFieldProgress(tool_state["cmd_id"], tool_state["fields"][tool_state["cmd_id"]])
                else:
                    setFieldProgress(tool_state["cmd_id"], tool_state["fields"][tool_state["cmd_id"]])
                
                self.__updateGUIUponStateImport(tool_state["cmd_id"])
            else:
                # Keywriter mode
                pass
        except:
            messagebox.showerror("", "Something went wrong")
    
    ###################################
    # FUNCTIONS TO SAVE / RESTORE - END
    ###################################





    def __actionFlagsInfo(self):
        """
        """
        custom_message_box(self, "Action Flags", """
Write Protect:
When enabled, prevents any future writes to this field.

Read Protect:
When enabled, prevents any future reads of this field. This provides security by making the field value unreadable after programming.

Override:
When enabled, allows programming fields by overriding their current value. For example, to change a revision value, override must be enabled. If the efuse rows corresponding to the key are not write protected, then enabling the override flag would attempt to program the efuse rows. Depending on the value, efuse programming may succeed or fail. For example, efuse row has data 0x11 (no write protect), and override is enabled. If the new value is 0x33, then it will be programmed. In case the new value is 0x22, it will fail since there would be an attempt to reset the bits at index 0 and 4.

Active/Inactive:
When enabled, indicates that this field should be programmed with the provided input value. This essentially controls whether the field is included in the current programming operation. Disabling this field would skip programming the field.
The usage of the active/inactive depends on the programming mode:

In single-shot mode, all fields must have the active enabled.
In multi-shot mode, only the fields you want to program should have the active enabled.
In specific field modes (like SMPKH mode, key count mode, etc.), the active must be enabled for the single field being programmed
""", width=60, height=15)
        

    def showDisclaimer(self):
         custom_message_box(self, "Disclaimer", disclaimer, width=60, height=15)

    def launch(self):
        """
        This function will launch the user interface when invoked. Internally this function invokes the mainloop()
        function on the application main window object
        """
        self.root0.mainloop()

APP = App()

if __name__ == "__main__":
    #launching the user interface
    APP.launch()
