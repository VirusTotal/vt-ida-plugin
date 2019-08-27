# Copyright (c) 2019 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'gerardofn@virustotal.com'

import idaapi
import idc
import idautils
import webbrowser
import urllib

class VTGrep_wildcards(idaapi.action_handler_t):
    """ Interface for searching patterns in VTGrep using wildcards """

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()

        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),
            instance.get_label(),
            instance
        ))

    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        self.plugin.search_with_wildcards()

        return 1

    @classmethod
    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM

class VTGrep_bytes(idaapi.action_handler_t):
    """ Interface for searching bytes in VTGrep """

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()

        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),
            instance.get_label(),
            instance
        ))

    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        self.plugin.search_for_bytes()
        return 1

    @classmethod
    def update(self, ctx):
        try:
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except:
            return idaapi.AST_ENABLE_ALWAYS

class Bytes():
    """ Class to represent Bytes in a search query """

    bytes_stream = ""

    def __init__(self, buffer):
        self.bytes_stream = buffer

    def append(self, slice):
        if not isinstance(slice, Bytes):
            self.bytes_stream = self.bytes_stream + slice
        else:
            self.bytes_stream = self.bytes_stream + slice.get()

    def get(self):
        return self.bytes_stream
    
    def len(self):
        return len(self.bytes_stream)

    def isWildCards(self):
        return False

    def isBytes(self):
        return True

    def sameType(self, object):
        if isinstance(object, Bytes):
            return True
        else:
            return False

class WildCards():
    """ Class to represent a set of WildCards used in a search query """

    wcs_stream = ""
    packed = False

    def __init__(self, buffer):
        self.wcs_stream = buffer
        self.pack()

    def append(self, slice): # slice can be a WildCards instance or a string of wildcards
        if not self.packed and not isinstance(slice, WildCards):
            self.wcs_stream = self.wcs_stream + slice
            self.pack()
        else:
            if isinstance(slice, WildCards):
                wcs_len = self.len() + slice.len()
            else:
                wcs_len = self.len() + len(slice)
 
            wcs_count = wcs_len / 2            
            self.wcs_stream = "[" + str(wcs_count) + "]" + "?" * (wcs_len % 2)
            self.packed = True

    def get(self):
        return self.wcs_stream

    def len(self):
        str_len = 0
        if self.packed:
            wcs_len = self.wcs_stream.lstrip("[").rstrip("]")
            question_index = self.wcs_stream.find('?')
            if question_index != -1:
                str_len = int(wcs_len.rstrip("]?")) * 2
                str_len += 1
            else:
                str_len = int(wcs_len) * 2
            return str_len
        else:
            return len(self.wcs_stream)

    def pack(self):
        if not self.packed:
            wcs_len = len(self.wcs_stream)
            if wcs_len > 3:
                wcs_count = (wcs_len / 2)
                self.wcs_stream = "[" + str(wcs_count) + "]" + "?" * (wcs_len % 2)
                self.packed = True

    def unpack(self):
        if self.packed:
            wcs_len = self.len()
            self.wcs_stream = "?" * wcs_len

    def isWildCards(self):
        return True

    def isBytes(self):
        return False 

    def sameType(self, object):
        if isinstance(object, WildCards):
            return True
        else:
            return False

class Popup(idaapi.UI_Hooks):
    """ Class to implement the right click operations that presents the options to interact with VTE """

    if idaapi.IDA_SDK_VERSION >= 700:
        # IDA >= 7
        def finish_populating_widget_popup(self, form, popup):
            if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
                idaapi.attach_action_to_popup(form, popup, VTGrep_wildcards.get_name(), "VTGrep/")
                idaapi.attach_action_to_popup(form, popup, VTGrep_bytes.get_name(), "VTGrep/")
    else:
        # IDA < 7
        def finish_populating_tform_popup(self, form, popup):
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                idaapi.attach_action_to_popup(form, popup, VTGrep_wildcards.get_name(), "VTGrep/")
                idaapi.attach_action_to_popup(form, popup, VTGrep_bytes.get_name(), "VTGrep/")


class VTGrep_Search():
    """ 
    VTGrep main class that implements all the methods to launch querys to VTGrep 
    
    This class implements the whole process of receiving a range of memory addresses, reading all the bytes and 
    transforming them (if desired) using wildcards to avoid memory address.
    """

    ea = 0
    url = ""
    addr_start = 0
    addr_end = 0
    query_list = []
    _MIN_QUERY_SIZE = 7
    _MAX_QUERY_SIZE = 1800

    def __init__(self, start, end):
        self.addr_start = start
        self.addr_end = end

    def set_wildcards(self, pattern, addr, len):
        """ Replace volatile bytes (calls and some jumps parameters) by using wildcards characters """

        len = idc.ItemSize(addr)

        inst_prefix = idc.GetManyBytes(addr, 1).encode("hex")

        if inst_prefix == "0f" or inst_prefix == "f2" or inst_prefix == "f3":  # Opcode Prefix (Intel x86)
            pattern = idc.GetManyBytes(addr, 2).encode("hex")
            ins_num_bytes = 2
        else:
            pattern = inst_prefix  # No prefix is used
            ins_num_bytes = 1
        
        pattern += " " + "??" * (len - ins_num_bytes) + " "      
        return pattern

    def get_opcodes(self, addr):
        """ Identify the instruction located at addr in order to replace parameters with wildcards """

        OFFSETS = [idaapi.o_far, idaapi.o_mem]
        pattern = ""

        if idaapi.IDA_SDK_VERSION >= 700:
            op1_type = idc.get_operand_type(addr, 0)
            op2_type = idc.get_operand_type(addr, 1)
        else:
            op1_type = idc.GetOpType(addr, 0)
            op2_type = idc.GetOpType(addr, 1)

        ins_len = idc.ItemSize(addr)
        mnem = idautils.DecodeInstruction(addr)

        if op1_type in OFFSETS or op2_type in OFFSETS:
            pattern = self.set_wildcards(pattern, addr, ins_len)
        else:
            if (mnem.itype == idaapi.NN_call) or (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near):
                pattern = self.set_wildcards(pattern, addr, ins_len)
            else:
                pattern = idc.GetManyBytes(addr, ins_len).encode("hex")  
        return pattern

    def generate_slices(self, buffer):
        """ Navigate through a string buffer generating WildCards and Bytes objects """
        
        list_slices = buffer.split()

        for slice in list_slices:
            if slice[0] == "?":
                yield WildCards(slice)
            else:
                yield Bytes(slice)

    def create_query(self, buffer):
        """ Receives a string buffer and produces a query compatible with VTGrep """

        query_slices = self.generate_slices(buffer)

        for slice in query_slices:
            if not self.query_list:  
                  self.query_list.append(slice)
            else:
                query_prev = len(self.query_list) - 1

                if not (slice.sameType(self.query_list[query_prev])):
                    self.query_list.append(slice)
                else:
                    self.query_list[query_prev].append(slice)              

        return self.sanitize()

    def sanitize(self):
        """ 
            Apply some checks to the current query before sending it to VTGrep 
            Checks performed:
            - No ending [] 
            - No consecutive [][]
            - No consecutive byte strings 
            - More than 4 bytes between []
        """

        query_len = len(self.query_list)
        restart = False
        slice_index = 0

        while (slice_index < query_len):

            slice = self.query_list[slice_index] 
            next_slice_index = slice_index + 1

            if (next_slice_index) != query_len:
                next_slice = self.query_list[next_slice_index]
            else:
                next_slice = ""

            if not next_slice: # Last slice
                if (slice.isBytes() and slice.len() < 8) or slice.isWildCards():
                    self.query_list.pop(slice_index)
                    restart = True
                break
            else:
                if slice.sameType(next_slice):
                    self.query_list[slice_index].append(next_slice)
                    self.query_list.pop(next_slice_index)
                    restart = True
                    break
                else:
                    if slice.isBytes() and (slice.len() < 8) and next_slice.isWildCards():
                        wcs_stream = "?" * slice.len()    
                        self.query_list[next_slice_index].append(wcs_stream)
                        self.query_list.pop(slice_index)          
                        restart = True
                        break
                    else:
                        slice_index += 1
        if restart:
            return self.sanitize()
        else:
            buffer = "".join(str(element.get()) for element in self.query_list)
            return buffer          

    def search(self, wildcards=False):
        """ Checks the current bytes selected in IDA Pro, call the appropriate method for generating a valid 
            query for VTGrep and open the web browser to launch the query """

        current = self.addr_start
        str_buf = ""
 
        if (self.addr_start == idaapi.BADADDR) or (self.addr_end == idaapi.BADADDR):
            print "[VT plugin] ERROR! Select a valid area to query VTGrep."
        else:
            if wildcards:
                while current < self.addr_end:
                    str_buf += self.get_opcodes(current)
                    if idaapi.IDA_SDK_VERSION >= 700:
                        current = idc.next_head(current)
                    else:
                        current = idc.NextHead(current)
                str_buf = self.create_query(str_buf)
            else:
                str_buf = idc.GetManyBytes(self.addr_start, self.addr_end - self.addr_start).encode("hex")

            if self._MIN_QUERY_SIZE < len(str_buf) < self._MAX_QUERY_SIZE:
                self.url = urllib.quote("www.virustotal.com/gui/search/content:{" + str_buf + "}/files")
                try:           
                    webbrowser.open(self.url, new=True)
                except Exception as e:
                    print "[VT plugin] ERROR! While opening web browser: " % e
                del self.query_list[:]
            else:
                print "[VT plugin] ERROR! Invalid query length (must be between 8 and 136)."


class VT_t(idaapi.plugin_t):
    """ Plugin interface """

    flags = idaapi.PLUGIN_UNL
    comment = "VirusTotal plugin for IDA Pro"
    help = "This plugin integrates some services from VirusTotal Enterprise into IDA Pro"
    wanted_name = "VT_plugin"
    wanted_hotkey = ""
    VERSION = "0.1"

    def init(self):
        """ Set up menu options and shows the welcoming message """
        self.menu = Popup()
        self.menu.hook()

        try:
            VTGrep_wildcards.register(self, "Search with wildcards")
            VTGrep_bytes.register(self, "Search bytes")

            if idaapi.IDA_SDK_VERSION >= 700:
                idaapi.attach_action_to_menu("Edit/VTGrep/", VTGrep_wildcards.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/VTGrep/", VTGrep_bytes.get_name(), idaapi.SETMENU_APP)
            else:
                idaapi.add_menu_item("Edit/VTGrep/", VTGrep_wildcards.get_name(), "", 1, self.searc_with_wildcards, None)
                idaapi.add_menu_item("Edit/VTGrep/", VTGrep_bytes.get_name(), "", 1, self.search_for_bytes, None)
        except:
            pass

        print "- - " * 20
        print("VT plugin for IDA Pro v{0} (c) Google, 2019".format(self.VERSION))
        print("\n This plugin integrates some functionalities of VirusTotal Enterprise into IDA Pro")
        print "- - " * 20
        return idaapi.PLUGIN_KEEP

    def search_with_wildcards(self):

        if idaapi.IDA_SDK_VERSION >= 700:
            search = VTGrep_Search(idc.read_selection_start(), idc.read_selection_end())
        else:
            sel, sel_start, sel_end = idaapi.read_selection()
            search = VTGrep_Search(sel_start, sel_end)

        search.search(True)

    def search_for_bytes(self):

        if idaapi.IDA_SDK_VERSION >= 700:
            search = VTGrep_Search(idc.read_selection_start(), idc.read_selection_end())
        else:
            sel, sel_start, sel_end = idaapi.read_selection()
            search = VTGrep_Search(sel_start, sel_end)

        search.search(False)

    def run(self, arg):
        pass

    def term(self):
        if self.menu != None:
            self.menu.unhook()


def PLUGIN_ENTRY():
    return VT_t()
