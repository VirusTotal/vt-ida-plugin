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

import ida_kernwin
import idaapi
import idc
import logging
from vt_ida import config
from vt_ida import vtgrep


def PLUGIN_ENTRY():
  return VTplugin()


class VTGrepStrings(idaapi.action_handler_t):
  """Performs the right click operation: Search for string."""

  @classmethod
  def get_name(cls):
    return cls.__name__

  @classmethod
  def get_label(cls):
    return cls.label

  @classmethod
  def activate(cls, ctx):
    for idx in ctx.chooser_selection:
      _, _, _, selected_string = ida_kernwin.get_chooser_data(
          ctx.widget_title,
          idx
          )
      cls.plugin.search_string(selected_string)
    return 0

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
  def update(cls, ctx):
    if ctx.form_type == idaapi.BWN_STRINGS:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET
    else:
      return ida_kernwin.AST_DISABLE_FOR_WIDGET


class VTGrepWildcards(idaapi.action_handler_t):
  """Performs the right click operation: Search for wildcards."""

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
    cls.plugin.search_with_wildcards(False)
    return 1

  @classmethod
  def update(cls, ctx):
    if ctx.form_type == idaapi.BWN_DISASM:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET
    else:
      return ida_kernwin.AST_DISABLE_FOR_WIDGET


class VTGrepWildCardsStrict(VTGrepWildcards):
  """Performs the right click operation: Search for wildcards (strict)."""

  @classmethod
  def activate(cls, ctx):
    cls.plugin.search_with_wildcards(True)
    return 1


class VTGrepWildCardsFunction(VTGrepWildcards):
  """Performs the right click operation: Search for similar function."""

  @classmethod
  def activate(cls, ctx):
    cls.plugin.search_function_with_wildcards()
    return 1


class VTGrepBytes(idaapi.action_handler_t):
  """Performs the right click operation: Search for bytes."""

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
    if ctx.form_type == idaapi.BWN_DISASM:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET
    else:
      return ida_kernwin.AST_DISABLE_FOR_WIDGET


class Popups(idaapi.UI_Hooks):
  """Declares methods to be called on right click operations."""

  @staticmethod
  def finish_populating_widget_popup(form, popup):
    if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
      idaapi.attach_action_to_popup(
          form,
          popup,
          VTGrepBytes.get_name(),
          'VirusTotal/'
          )
      idaapi.attach_action_to_popup(
          form,
          popup,
          VTGrepWildcards.get_name(),
          'VirusTotal/',
          )
      idaapi.attach_action_to_popup(
          form,
          popup,
          VTGrepWildCardsStrict.get_name(),
          'VirusTotal/',
          )
      idaapi.attach_action_to_popup(
          form,
          popup,
          VTGrepWildCardsFunction.get_name(),
          'VirusTotal/',
          )
    elif idaapi.get_widget_type(form) == idaapi.BWN_STRINGS:
      idaapi.attach_action_to_popup(
          form,
          popup,
          VTGrepStrings.get_name(),
          'VirusTotal/')


class VTplugin(idaapi.plugin_t):
  """VirusTotal plugin interface for IDA Pro."""

  SUPPORTED_PROCESSORS = ['80286r', '80286p', '80386r', '80386p', '80486r',
                          '80486p', '80586r', '80586p', '80686p', 'k62', 'p2',
                          'p3', 'athlon', 'p4', 'metapc']
  flags = idaapi.PLUGIN_UNL
  comment = 'VirusTotal plugin for IDA Pro'
  help = 'VirusTotal integration plugin for Hex-Ray\'s IDA Pro 7'
  wanted_name = 'VT_Plugin'
  wanted_hotkey = ''

  def init(self):
    """Set up menu hooks and implements search methods."""

    self.menu = Popups()
    self.menu.hook()
    arch_info = idaapi.get_inf_structure()

    try:
      if arch_info.procName in self.SUPPORTED_PROCESSORS:
        VTGrepWildcards.register(self, 'Search for similar code')
        VTGrepWildCardsStrict.register(self, 'Search for similar code (strict)')
        VTGrepWildCardsFunction.register(self, 'Search for similar function')
      else:
        logging.info('\n - Processor detected: %s', arch_info.procName)
        logging.info(' - Searching for similar code is not available.')
      VTGrepBytes.register(self, 'Search for bytes')
      VTGrepStrings.register(self, 'Search for string')

    except:
      logging.error('[VT Plugin] Unable to register popups actions.')

    return idaapi.PLUGIN_KEEP

  @staticmethod
  def search_string(selected_string):
    search_vt = vtgrep.VTGrepSearch(string=selected_string)
    search_vt.search(False)

  @staticmethod
  def search_with_wildcards(strict):
    search_vt = vtgrep.VTGrepSearch(
        addr_start=idc.read_selection_start(),
        addr_end=idc.read_selection_end()
        )
    search_vt.search(True, strict)

  @staticmethod
  def search_function_with_wildcards():
    addr_current = idc.get_screen_ea()
    addr_func = idaapi.get_func(addr_current)

    if not addr_func:
      logging.error('[VT Plugin] Current address doesn\'t belong to a function')
    else:
      search_vt = vtgrep.VTGrepSearch(
          addr_start=addr_func.start_ea,
          addr_end=addr_func.end_ea
          )
      search_vt.search(True, False)

  @staticmethod
  def search_for_bytes():
    search_vt = vtgrep.VTGrepSearch(
        addr_start=idc.read_selection_start(),
        addr_end=idc.read_selection_end()
        )
    search_vt.search(False)

  @staticmethod
  def run(arg):
    pass

  def term(self):
    if self.menu:
      self.menu.unhook()



