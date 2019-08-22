import idaapi
import idc
import idautils
import webbrowser
import urllib


_MIN_QUERY_SIZE = 7
_MAX_QUERY_SIZE = 1800
VERSION = "0.1"


class Popup(idaapi.UI_Hooks):
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


class VTGrep_wildcards(idaapi.action_handler_t):

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


class VTGrep_Search():
    ea = 0
    url = ""
    addr_start = 0
    addr_end = 0

    def __init__(self, start, end):
        self.addr_start = start
        self.addr_end = end

    def add_wildcards(self, pattern, addr, len):
        len = idc.ItemSize(addr)

        inst_prefix = idc.GetManyBytes(addr, 1).encode("hex")

        if inst_prefix == "0f" or inst_prefix == "f2" or inst_prefix == "f3":  # Opcode Prefix (Intel x86)
            pattern = idc.GetManyBytes(addr, 2).encode("hex")
            j = 2
        else:
            pattern = inst_prefix  # No prefix is used
            j = 1

        for i in range(j, len):
            pattern += "??"
        return pattern

    def get_opcodes(self, addr):
        OFFSETS = [idaapi.o_far, idaapi.o_mem]
        pattern = ""

        if idaapi.IDA_SDK_VERSION >= 700:
            op1_type = idc.get_operand_type(addr, 0)
            op2_type = idc.get_operand_type(addr, 1)
        else:
            op1_type = idc.GetOpType(addr, 0)
            op2_type = idc.GetOpType(addr, 1)

        len = idc.ItemSize(addr)
        mnem = idautils.DecodeInstruction(addr)

        if op1_type in OFFSETS or op2_type in OFFSETS:
            pattern = self.add_wildcards(pattern, addr, len)
        else:
            if (mnem.itype == idaapi.NN_call) or (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near):
                pattern = self.add_wildcards(pattern, addr, len)
            else:
                pattern = idc.GetManyBytes(addr, len).encode("hex")  
        return pattern

        
    def sanitize(self, buffer):
        oc = 0
        bl = len(buffer)

        # Search for sets of <4 bytes between wildcards
        for i in range(0, bl):
            if buffer[i] == "?":
                if oc < 8 and oc != 0:
                    j = i - oc
                    wc_str = "?" * oc
                    if j == 0:
                        buffer = wc_str + buffer[i:bl]
                    else:
                        buffer = buffer[0:j] + wc_str + buffer[i:bl]
                oc = 0
            else:
                if buffer[i] != " ":
                    oc += 1

        if oc < 8 and oc != 0:  # Search for a set of <4 bytes at the end of the query
            j = i - oc + 1
            wc_str = "?" * oc
            buffer = buffer[0:j] + wc_str

        buffer = buffer.rstrip("?")
        num_wcs = 0
        start_wcs = 0
        bl = len(buffer)
        i = 0
        
        # Look for more than 4 "?" wildcard characters and replace them with "[]"" wildcards.
        while i < bl:
            if buffer[i] == "?":
                num_wcs += 1
                if num_wcs == 1:
                    start_wcs = i
                i += 1
            else:
                if num_wcs > 3 and (num_wcs % 2 == 0):
                    wcs_index = (num_wcs / 2)
                    wcs_str = "[" + str(wcs_index) + "]"
                    buffer = buffer[0:start_wcs] + wcs_str + buffer[(start_wcs + num_wcs):]
                    bl = len(buffer)
                    i = start_wcs + len(wcs_str) + 1
                else:
                    i += 1
                start_wcs = 0
                num_wcs = 0
        return buffer

    def search(self, wildcards=False):
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
                str_buf = self.sanitize(str_buf)
            else:
                str_buf = idc.GetManyBytes(self.addr_start, self.addr_end - self.addr_start).encode("hex")

            if _MIN_QUERY_SIZE < len(str_buf) < _MAX_QUERY_SIZE:
                self.url = urllib.quote("www.virustotal.com/gui/search/content:{" + str_buf + "}/files")
                try:           
                    webbrowser.open(self.url, new=True)
                except Exception as e:
                    print "[VT plugin] ERROR! While opening web browser: " % e
            else:
                print "[VT plugin] ERROR! Invalid query length (must be between 8 and 136)."


class VT_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "VirusTotal plugin for IDA Pro"
    help = "This plugin integrates some services from VirusTotal Enterprise into IDA Pro"
    wanted_name = "VT_plugin"
    wanted_hotkey = "Alt-V"

    def init(self):
        self.menu = Popup()
        self.menu.hook()

        try:
            VTGrep_wildcards.register(self, "Search with wildcards")
            VTGrep_bytes.register(self, "Search bytes")

            if idaapi.IDA_SDK_VERSION >= 700:
                idaapi.attach_action_to_menu("Edit/VTGrep/", VTGrep_wildcards.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/VTGrep/", VTGrep_bytes.get_name(), idaapi.SETMENU_APP)
            else:
                idaapi.add_menu_item("Edit/VTGrep/", VTGrep_wildcards.get_name(), "", 1, self.searc_with_wildcards,
                                     None)
                idaapi.add_menu_item("Edit/VTGrep/", VTGrep_bytes.get_name(), "", 1, self.search_for_bytes, None)
        except:
            pass

        print "- - " * 20
        print("VT plugin for IDA Pro v{0} (c) Google, 2019".format(VERSION))
        print("Shortcut key is Alt-F10")
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
