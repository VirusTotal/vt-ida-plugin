# Copyright 2019 Google Inc. All Rights Reserved.
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
from vt_ida.vtgrep import VTGrepSearch

def PLUGIN_ENTRY():
  return VTplugin()


class VTGrepWildcards(idaapi.action_handler_t):
  """IDA interface for VTplugin.search_with_wildcards() method."""

  @classmethod
  def get_name(cls):
    return cls.__name__

  @classmethod
  def get_label(cls):
    return cls.label

  @classmethod
  def register(cls, plugin, label):
    cls.plugin = plugin
    cls.label = label
    instance = cls()

    return idaapi.register_action(idaapi.action_desc_t(
        cls.get_name(),
        instance.get_label(),
        instance
        ))

  @classmethod
  def unregister(cls):
    idaapi.unregister_action(cls.get_name())

  @classmethod
  def activate(cls, ctx):
    cls.plugin.search_with_wildcards()
    return 1

  @classmethod
  def update(cls, ctx):
    if ctx.form_type == idaapi.BWN_DISASM:
      return idaapi.AST_ENABLE_FOR_FORM
    else:
      return idaapi.AST_DISABLE_FOR_FORM


class VTGrepBytes(idaapi.action_handler_t):
  """IDA interface for VTplugin.search_for_bytes() method."""

  @classmethod
  def get_name(cls):
    return cls.__name__

  @classmethod
  def get_label(cls):
    return cls.label

  @classmethod
  def register(cls, plugin, label):
    cls.plugin = plugin
    cls.label = label
    instance = cls()

    return idaapi.register_action(idaapi.action_desc_t(
        cls.get_name(),
        instance.get_label(),
        instance
        ))

  @classmethod
  def unregister(cls):
    idaapi.unregister_action(cls.get_name())

  @classmethod
  def activate(cls, ctx):
    cls.plugin.search_for_bytes()
    return 1

  @classmethod
  def update(cls, ctx):
    try:
      if ctx.form_type == idaapi.BWN_DISASM:
        return idaapi.AST_ENABLE_FOR_FORM
      else:
        return idaapi.AST_DISABLE_FOR_FORM
    except:
      return idaapi.AST_ENABLE_ALWAYS


class Popup(idaapi.UI_Hooks):
  """Implements the right click operations in the UI."""

  if idaapi.IDA_SDK_VERSION >= 700:
    # IDA >= 7

    @staticmethod
    def finish_populating_widget_popup(form, popup):
      if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
        idaapi.attach_action_to_popup(
            form,
            popup,
            VTGrepWildcards.get_name(),
            'VTGrep/',
            )
        idaapi.attach_action_to_popup(
            form,
            popup,
            VTGrepBytes.get_name(),
            'VTGrep/'
            )
  else:
    # IDA < 7

    @staticmethod
    def finish_populating_tform_popup(form, popup):
      if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
        idaapi.attach_action_to_popup(
            form,
            popup,
            VTGrepWildcards.get_name(),
            'VTGrep/',
            )
        idaapi.attach_action_to_popup(
            form,
            popup,
            VTGrepBytes.get_name(),
            'VTGrep/'
            )


class VTplugin(idaapi.plugin_t):
  """VirusTotal plugin interface for IDA Pro."""

  flags = idaapi.PLUGIN_UNL
  comment = 'VirusTotal plugin for IDA Pro'
  help = 'This plugin integrates some services from VirusTotal Enterprise'
  wanted_name = 'VT_plugin'
  wanted_hotkey = ''
  VERSION = '0.1'

  def init(self):
    """Set up menu options and shows the welcoming message."""
    self.menu = Popup()
    self.menu.hook()

    try:
      VTGrepWildcards.register(self, 'Search with wildcards')
      VTGrepBytes.register(self, 'Search bytes')

      if idaapi.IDA_SDK_VERSION >= 700:
        idaapi.attach_action_to_menu(
            'Edit/VTGrep/',
            VTGrepWildcards.get_name(),
            idaapi.SETMENU_APP
            )
        idaapi.attach_action_to_menu(
            'Edit/VTGrep/',
            VTGrepBytes.get_name(),
            idaapi.SETMENU_APP
            )
      else:
        idaapi.add_menu_item(
            'Edit/VTGrep/',
            VTGrepWildcards.get_name(),
            '',
            1,
            self.searc_with_wildcards,
            None
            )
        idaapi.add_menu_item(
            'Edit/VTGrep/',
            VTGrepBytes.get_name(),
            '',
            1,
            self.search_for_bytes,
            None
            )
    except:
      print '[VT plugin] ERROR! Unable to create menu items.'
      pass

    print '- - ' * 21
    print 'VT plugin for IDA Pro v{0} (c) Google, 2019'.format(self.VERSION)
    print 'VirusTotal Enterprise integration plugin for IDA Pro 6/7'
    print '\nSelect instructions and right click to search on VTGrep'
    print '- - ' * 21

    return idaapi.PLUGIN_KEEP

  @staticmethod
  def search_with_wildcards():
    if idaapi.IDA_SDK_VERSION >= 700:
      search = VTGrepSearch(
          idc.read_selection_start(),
          idc.read_selection_end()
          )
    else:
      sel, sel_start, sel_end = idaapi.read_selection()
      search = VTGrepSearch(sel_start, sel_end)

    search.search(True)

  @staticmethod
  def search_for_bytes():
    if idaapi.IDA_SDK_VERSION >= 700:
      search = VTGrepSearch(
          idc.read_selection_start(),
          idc.read_selection_end()
          )
    else:
      sel, sel_start, sel_end = idaapi.read_selection()
      search = VTGrepSearch(sel_start, sel_end)

    search.search(False)

  @staticmethod
  def run(arg):
    pass

  def term(self):
    if self.menu:
      self.menu.unhook()



