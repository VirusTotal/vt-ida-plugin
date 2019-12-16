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

import sys
import ConfigParser
import hashlib
import ida_kernwin
import idaapi
import idc
import logging
import os
import requests
from vt_ida import config
from vt_ida import vtgrep

VT_VERSION = '0.5'

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


class WarningForm(ida_kernwin.Form):

  def __init__(self):
    self.invert = False
    ida_kernwin.Form.__init__(self, r"""STARTITEM 0
BUTTON YES* Ok
BUTTON NO  No
VirusTotal Plugin for IDA Pro 7

Welcome to the Beta Version of VirusTotal IDA Pro Plugin !

*** * *** * *** * *** * *** * *** * *** * *** * *** * *** *
In order for this plugin to work, write your API KEY in the 
"config.py" file. 
*** * *** * *** * *** * *** * *** * *** * *** * *** * *** *

Auto uploads of samples is enabled by default. By submitting 
your file to VirusTotal you are asking VirusTotal to share 
your submission with the security community and agree to our 
Terms of Service and Privacy Policy. 

For further information click on the following links:
- {cHtml1}
- {cHtml2}

Press "Ok" to agree, "No" to disable uploads or "Cancel"
to stop using this plugin.
 
""", {
    'cHtml1': ida_kernwin.Form.StringLabel(
        '<a href=\"https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service\">Terms of Service</a>',
        tp=ida_kernwin.Form.FT_HTML_LABEL
    ),
    'cHtml2': ida_kernwin.Form.StringLabel(
        '<a href=\"https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy\">Privacy Policy</a>',
        tp=ida_kernwin.Form.FT_HTML_LABEL
    )
})


class VTpluginSetup(object):
  """Check and setup global parameters."""

  auto_upload = True
  vt_cfgfile = ''
  valid_setup = False
  file_path=''
  file_name=''

  @staticmethod
  def show_warning():
    """Shows a popup window to ask for user consent in order to upload files."""

    warning_f = WarningForm()
    warning_f.Compile()
    change_config = warning_f.Execute()
    warning_f.Free()

    return change_config

  def read_config(self):
    """Read user's configuration file."""

    logging.debug('[VT Plugin] Reading user config file: %s', self.vt_cfgfile)
    config_file = ConfigParser.RawConfigParser()
    config_file.read(self.vt_cfgfile)

    try:
      if config_file.get('General', 'auto_upload') == 'True':
        self.auto_upload = True
      else:
        self.auto_upload = False
      return True
    except:
      logging.error('[VT Plugin] Error reading the user config file.')
      return False

  def write_config(self):
    """Write user's configuration file."""

    logging.debug('[VT Plugin] Writing user config file: %s', self.vt_cfgfile)

    try:
      parser = ConfigParser.ConfigParser()
      config_file = open(self.vt_cfgfile, 'w')
      parser.add_section('General')
      parser.set('General', 'auto_upload', self.auto_upload)
      parser.write(config_file)
      config_file.close()
    except:
      logging.error('[VT Plugin] Error while creating user config file.')
      return False
    return True

  def check_hash(self):
    """Return True if the file is not available at VirusTotal."""

    user_agent = 'IDA Pro VT Plugin checkhash - v' + VT_VERSION
    headers = { 
      'User-Agent': user_agent,
      'x-apikey': '', 
      'Accept': 'application/json'
    }
    headers['x-apikey'] = config.API_KEY

    if os.path.isfile(self.file_path): 
      # Only checks the hash value when the input file is available

      hash_f = hashlib.sha256()
      file_r = open(self.file_path, 'rb')

      for file_buffer in iter(lambda: file_r.read(8192), b''):
        hash_f.update(file_buffer)

      file_hash = hash_f.hexdigest()
      url = 'https://www.virustotal.com/api/v3/files/%s' % file_hash

      try:
        logging.debug('[VT Plugin] Checking hash: %s', file_hash)
        response = requests.get(url, headers=headers)
        if response.status_code == 404:  # file not found in VirusTotal
          return True
        else:
          logging.debug('[VT Plugin] File already available in VirusTotal.')
      except:
        logging.error('[VT Plugin] Unable to connect to VirusTotal.com')

    return False

  def upload_file(self):
    """Upload input file to VirusTotal."""

    user_agent = 'IDA Pro VT Plugin upload - v' + VT_VERSION

    headers = { 
      'User-Agent': user_agent,
      'x-apikey': '', 
      'Accept': 'application/json'
    }
    headers['x-apikey'] = config.API_KEY

    if os.path.isfile(self.file_path):
      try:
        logging.info('[VT_Plugin] Uploading input file to VirusTotal.')
        url = 'https://www.virustotal.com/api/v3/files'
        files = {'file': (self.file_name, open(self.file_path, 'rb'))}

        response = requests.post(url, files=files, headers=headers)

        if response.status_code == 200:
          logging.debug('[VT Plugin] Uploaded successfully.')
        else:
          logging.error('[VT Plugin] Upload failed.')
      except:
        logging.error('[VT Plugin] Unable to connect to VirusTotal.com')
    else:
      logging.error('[VT Plugin] Uploading error: input file path is invalid.')

  def __init__(self, cfgfile):
    self.vt_cfgfile = cfgfile
    self.file_path = idaapi.get_input_file_path()
    self.file_name = idc.get_root_filename()

    if config.DEBUG:
      logging.basicConfig(
          stream=sys.stdout,
          level=logging.DEBUG,
          format='%(message)s'
          )
    else:
      logging.basicConfig(
          stream=sys.stdout,
          level=logging.INFO,
          format='%(message)s'
          )

    logging.info('\n** VT Plugin for IDA Pro v%s (c) Google, 2019', VT_VERSION)
    logging.info('** VirusTotal integration plugin for Hex-Ray\'s IDA Pro 7')

    logging.info('\n** Select an area in the Disassembly Window and right')
    logging.info('** click to search on VirusTotal. You can also select a')
    logging.info('** string in the Strings Window.\n')

    if not config.API_KEY:
      logging.info('[VT_Plugin] No API KEY defined in the \'config.py\' file. ')
      return None


class VTplugin(idaapi.plugin_t):
  """VirusTotal plugin interface for IDA Pro."""

  SUPPORTED_PROCESSORS = ['80286r', '80286p', '80386r', '80386p', '80486r',
                          '80486p', '80586r', '80586p', '80686p', 'k62', 'p2',
                          'p3', 'athlon', 'p4', 'metapc']
  flags = idaapi.PLUGIN_UNL
  comment = 'VirusTotal Plugin for IDA Pro'
  help = 'VirusTotal integration plugin for Hex-Ray\'s IDA Pro 7'
  wanted_name = 'VirusTotal'
  wanted_hotkey = ''

  def init(self):
    """Set up menu hooks and implements search methods."""

    valid_config = False
    config_file = os.path.join(idaapi.get_user_idadir(), 'virustotal.conf')
    vtsetup = VTpluginSetup(config_file)

    if os.path.exists(config_file):
      valid_config = vtsetup.read_config()
    else:
      answer = vtsetup.show_warning()
      if answer == 1:     # OK
        vtsetup.auto_upload = True
        valid_config = vtsetup.write_config()
      elif answer == 0:   # NO
        vtsetup.auto_upload = False
        valid_config = vtsetup.write_config()
      elif answer == -1:  # Cancel
        valid_config = False

    if valid_config:
      if vtsetup.check_hash() and vtsetup.auto_upload:
        vtsetup.upload_file()

      self.menu = Popups()
      self.menu.hook()
      arch_info = idaapi.get_inf_structure()

      try:
        if arch_info.procName in self.SUPPORTED_PROCESSORS:
          VTGrepWildcards.register(self, 'Search for similar code')
          VTGrepWildCardsStrict.register(
              self,
              'Search for similar code (strict)'
          )
          VTGrepWildCardsFunction.register(self, 'Search for similar function')
        else:
          logging.info('\n - Processor detected: %s', arch_info.procName)
          logging.info(' - Searching for similar code is not available.')
        VTGrepBytes.register(self, 'Search for bytes')
        VTGrepStrings.register(self, 'Search for string')
      except:
        logging.error('[VT Plugin] Unable to register popups actions.')
    else:
      logging.info('[VT_Plugin] Plugin disabled, restart IDA to proceed. ')
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
