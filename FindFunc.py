#!/usr/bin/env python3
import idautils
import idc
import ida_idaapi as idaapi
import re
import ida_nalt
import ida_kernwin
import ida_funcs
import ida_gdl
import ida_name

regex = r"^\w+::\w+$"
plugin_init = False


# force rename wrapper
def rename_wrapper(name, func_addr):
    if ida_name.force_name(func_addr, name, ida_name.SN_NOCHECK):
        print(
            "Function at 0x%x renamed %s"
            % (func_addr, ida_funcs.get_func_name(func_addr))
        )
    else:
        print("Rename at 0x%x failed. Function %s is being used." % (func_addr, name))


try:

    class Kp_Menu_Context(ida_kernwin.action_handler_t):
        def __init__(self):
            ida_kernwin.action_handler_t.__init__(self)

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
            return ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    self.get_name(),  # Name. Acts as an ID. Must be unique.
                    instance.get_label(),  # Label. That's what users see.
                    instance,  # Handler. Called when activated, and for updating
                )
            )

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            ida_kernwin.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.widget_type == ida_kernwin.BWN_DISASM:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            mod_name = ida_kernwin.ask_str("", 0, "Enter import module name: ")
            fn_name = ida_kernwin.ask_str("", 0, "Enter import func name: ")
            self.plugin.search(mod_name, fn_name)
            return 1

except:
    pass


class CustomChooser(ida_kernwin.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", ida_kernwin.Choose.CHCOL_HEX | 10],
                ["Name", ida_kernwin.Choose.CHCOL_PLAIN | 25],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded,
        )
        self.items = items
        self.selcount = 0
        self.n = len(items[0])
        self.item_cmd_id = (
            self.append_item_cmd_id
        ) = None  # custom command handler stuff

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.item_cmd_id:
            rename_wrapper(self.items[1][n], self.items[0][n])
        return 0

    def set_item_handler(self, cmd_id):
        self.item_cmd_id = cmd_id

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[0][n])

    def OnGetLine(self, n):
        res = [idc.atoa(self.items[0][n]), self.items[1][n]]
        return res

    def OnGetSize(self):
        n = len(self.items[0])
        return n

    def show(self):
        return self.Show() >= 0


class FindFunc_Plugin_t(idaapi.plugin_t):
    comment = "FindFunc IDA Pro"
    help = "not today"
    wanted_name = "FindFunc"
    wanted_hotkey = "Ctrl-Alt-L"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global plugin_init

        # register popup menu handlers
        try:
            Searcher.register(self, "FindFunc")
        except:
            pass

        if plugin_init is False:
            plugin_init = True
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    "FindFunc",
                    "Find function names by string refs",
                    Searcher(),
                    None,
                    None,
                    0,
                )
            )
            ida_kernwin.attach_action_to_menu(
                "Search", "FindFunc", ida_kernwin.SETMENU_APP
            )

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def fix_str_bs(self, s):
        if s.endswith("'"):
            s = s.replace("'", "")
        if s.startswith("b"):
            s = s.replace("b", "", 1)
        s = s.replace("(", "", 1)
        s = s.replace(")", "", 1)
        s = s.replace("_", "")
        s += "_"
        return s

    def search(self, mod_name, fn_name):
        imports, res = self.find_import_refs(mod_name)
        found_strings = list()
        found_addrs = []
        for key, val in res.items():
            import_name = imports[key][1]
            import_addr = imports[key][0]

            if import_name.find(fn_name) >= 0:
                for xref in idautils.XrefsTo(import_addr):
                    call_addr = xref.frm
                    caller_name = ida_funcs.get_func_name(call_addr)
                    caller_func = ida_funcs.get_func(call_addr)

                    if caller_name.startswith("sub_") and caller_func:
                        for o, r, string in self.enum_string_refs_in_function(
                            call_addr
                        ):
                            if len(string) <= 0:
                                continue

                            string = self.fix_str_bs(string)
                            if (
                                re.match(regex, string)
                                and string not in found_strings
                                and caller_func.start_ea not in found_addrs
                            ):
                                if string.endswith("_"):
                                    string = string.replace("_", "")
                                found_strings.append(string)
                                found_addrs.append(caller_func.start_ea)

                            elif (
                                re.match(regex, string)
                                and string in found_strings
                                and caller_func.start_ea not in found_addrs
                            ):
                                string += hex(caller_func.start_ea)
                                string = string.replace("0x", "")
                                found_strings.append(string)
                                found_addrs.append(caller_func.start_ea)

        if len(found_strings) > 0:
            c = CustomChooser("FindFunc results", [found_addrs, found_strings])
            r = c.show()
            c.set_item_handler(c.AddCommand("Apply Name Change"))

    def find_imported_funcs(self, dllname):
        def imp_cb(ea, name, ord):
            if not name:
                name = ""
            imports.append([ea, name, ord])
            return True

        imports = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(0, nimps):
            name = ida_nalt.get_import_module_name(i)
            if re.match(dllname, name, re.IGNORECASE) is None:
                continue
            ida_nalt.enum_import_names(i, imp_cb)
        return imports

    def find_import_refs(self, dllname):
        imports = self.find_imported_funcs(dllname)
        R = dict()
        for i, (ea, name, _) in enumerate(imports):
            for xref in idautils.XrefsTo(ea):
                ea = xref.frm
                f = ida_funcs.get_func(ea)
                if f and (f.flags & ida_funcs.FUNC_THUNK) != 0:
                    imports.append([f.start_ea, ida_funcs.get_func_name(f.start_ea), 0])
                    continue
                if i not in R:
                    R[i] = []
                R[i].append(ea)
        return (imports, R)

    def enum_func_addr(self, ea):
        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError("not a function")

        for block in ida_gdl.FlowChart(func):
            iter_ea = block.start_ea
            while iter_ea <= block.end_ea:
                yield iter_ea
                iter_ea = idc.next_head(iter_ea)

    def enum_string_refs_in_function(self, ea):
        for iter_ea in self.enum_func_addr(ea):
            for ref in idautils.DataRefsFrom(iter_ea):
                type = idc.get_str_type(ref)
                if type not in range(0, 7) and type != 0x2000001:
                    continue
                CALC_MAX_LEN = -1
                string = str(idc.get_strlit_contents(ref, CALC_MAX_LEN, type))
                yield iter_ea, ref, string

    def run(self, arg):
        mod_name = ida_kernwin.ask_str("", 0, "Enter import module name: ")
        fn_name = ida_kernwin.ask_str("", 0, "Enter import func name: ")
        self.search(mod_name, fn_name)


# register IDA plugin
def PLUGIN_ENTRY():
    return FindFunc_Plugin_t()
