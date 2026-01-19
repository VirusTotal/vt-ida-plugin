# Copyright 2026 Google LLC. All Rights Reserved.
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
import hashlib
import ida_kernwin
import idaapi
import idc
import idautils
import logging
import os
import requests
import pathlib
import threading
from virustotal import config
from virustotal import vtgrep
from virustotal import codeinsight
from virustotal.vt_ida.vtpanel import VTPanel
from virustotal.vt_ida.vtwidgets import VTWidgets

if idaapi.IDA_SDK_VERSION >= 900:
  import ida_ida

try:
  import ConfigParser as configparser
except ImportError:
  import configparser

VT_IDA_PLUGIN_VERSION = '1.07'
widget_panel = VTPanel()

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

def PLUGIN_ENTRY():
  return VTplugin()

def calculate_hash(input_file):
  """Return hash if the file hash has been properly calculated."""

  file_hash = None
  
  try:
    path_obj = pathlib.Path(input_file)
  except Exception:
    logging.debug('[VT Plugin] Invalid path format: %s', input_file)
    path_obj = None

  if path_obj and path_obj.is_file():
    hash_f = hashlib.sha256()
    logging.debug('[VT Plugin] Input file available.')
    try:
      with path_obj.open('rb') as file_r:
        for file_buffer in iter(lambda: file_r.read(8192), b''):
          hash_f.update(file_buffer)
      file_hash = hash_f.hexdigest()
      logging.debug('[VT Plugin] Input file hash been calculated.')
    except:
      logging.debug('[VT Plugin] Can\'t load the input file.')
  else:
    logging.debug('[VT Plugin] Input file not available.')
    tmp_hash = idautils.GetInputFileMD5()
    if len(tmp_hash) != 32:
      logging.error('[VT Plugin] IDAPYTHON API returned a wrong hash value.')
    else:
      file_hash = tmp_hash

  if file_hash:
    return file_hash
  
  logging.error('[VT Plugin] Input file hash error.')
  return None


class CodeInsightASM(idaapi.action_handler_t):
  """Performs the right click operation: query Code Insight for disassembled code."""

  @classmethod
  def get_name(cls):
    return cls.__name__

  @classmethod
  def get_label(cls):
    return cls.label

  @classmethod
  def activate(cls, ctx):
    cls.plugin.query_codeinsight(code_type=codeinsight.CI_DISASSEMBLED)
    return 1

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
    global widget_panel

    if ctx.widget_type == idaapi.BWN_DISASM:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET
    else:
      return ida_kernwin.AST_DISABLE_FOR_WIDGET

class CodeInsightDecompiled(idaapi.action_handler_t):
  """Performs the right click operation: query Code Insight for decompiled code."""

  @classmethod
  def get_name(cls):
    return cls.__name__

  @classmethod
  def get_label(cls):
    return cls.label

  @classmethod
  def activate(cls, ctx):
    cls.plugin.query_codeinsight(code_type=codeinsight.CI_DECOMPILED)
    return 1

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
    global widget_panel
  
    if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET
    else:
      return ida_kernwin.AST_DISABLE_FOR_WIDGET

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
    if ctx.widget_type == idaapi.BWN_STRINGS:
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
    if ctx.widget_type == idaapi.BWN_DISASM:
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
    if ctx.widget_type == idaapi.BWN_DISASM:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET
    else:
      return ida_kernwin.AST_DISABLE_FOR_WIDGET


class MenuVTPanel(idaapi.action_handler_t):

  @classmethod
  def activate(cls, ctx):
    global widget_panel

    if len(config.API_KEY) > 0:
      # Find the panel if it already exists
      panel = ida_kernwin.find_widget("VirusTotal")
      if panel:
        # If it exists, just bring it to the front
        ida_kernwin.activate_widget(panel, True)
      else:
        # If it doesn't exist, create a new instance and show it.
        widget_panel = VTPanel()
        widget_panel.Show("VirusTotal")
        idaapi.set_dock_pos('VirusTotal', '', idaapi.DP_RIGHT)
        file_path = idaapi.get_input_file_path()
        widget_panel.set_data(fhash=calculate_hash(file_path))
    else:
      if len(config.API_KEY) == 0:
        logging.error('[VT Plugin] VirusTotal\'s API_KEY not configured or invalid.')
        VTWidgets.show_warning('A VirusTotal API Key has not been configured,\nplease indicate your API KEY in the \"config.py\" file.')

  @classmethod
  def update(cls, ctx):
    return ida_kernwin.AST_ENABLE_ALWAYS


class Popups(idaapi.UI_Hooks):
  """Declares methods to be called on right click operations."""

  @staticmethod
  def finish_populating_widget_popup(form, popup):
    if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
      idaapi.attach_action_to_popup(
          form,
          popup,
          CodeInsightASM.get_name(),
          'VirusTotal/',
          )
      idaapi.attach_action_to_popup(
            form,
            popup,
            None,
            "VirusTotal/",
            idaapi.SETMENU_INS
          )
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
    elif idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
      idaapi.attach_action_to_popup(
          form,
          popup,
          CodeInsightDecompiled.get_name(),
          'VirusTotal/')


class WarningForm(ida_kernwin.Form):

  def __init__(self):
    self.invert = False
    ida_kernwin.Form.__init__(self, r"""STARTITEM 0
BUTTON YES Ok
BUTTON NO*  No
BUTTON Cancel Cancel
VirusTotal Plugin for IDA Pro

Welcome to the Beta Version of the VirusTotal IDA Pro Plugin !

This plugin can be configured to automatically upload you 
samples. By submitting your file to VirusTotal you are asking 
VirusTotal to share your submission with the security community 
and agree to our Terms of Service and Privacy Policy. 

For further information click on the following links:
- {cHtml1}
- {cHtml2}

Press "Ok" to agree, "No" to disable uploads or "Cancel"
to stop using this plugin.
 
""", {
    'cHtml1': ida_kernwin.Form.StringLabel(
        '<a href=\"https://docs.virustotal.com/docs/terms-of-service\">Terms of Service</a>',
        tp=ida_kernwin.Form.FT_HTML_LABEL
    ),
    'cHtml2': ida_kernwin.Form.StringLabel(
        '<a href=\"https://docs.virustotal.com/docs/privacy-policy\">Privacy Policy</a>',
        tp=ida_kernwin.Form.FT_HTML_LABEL
    )
})
   

class CheckSample(threading.Thread):
  auto_upload = None
  input_file = None
  file_hash = None

  def __init__(self, upload, path):
    self.auto_upload = upload
    self.input_file = path
    self.file_hash = calculate_hash(input_file=path)
    threading.Thread.__init__(self)

  def check_file_missing_in_VT(self):
    """Return True if the file is not available at VirusTotal."""

    if config.API_KEY:
      user_agent = 'IDA Pro VT Plugin checkhash - v'
      user_agent += VT_IDA_PLUGIN_VERSION
      headers = {
          'User-Agent': user_agent,
          'Accept': 'application/json',
          'x-apikey': config.API_KEY
      }

      url = 'https://www.virustotal.com/api/v3/files/%s' % self.file_hash

      logging.debug('[VT Plugin] Checking hash: %s', self.file_hash)
      try:
        response = requests.get(url, headers=headers)
      except:
        logging.error('[VT Plugin] Unable to connect to VirusTotal.com')
        return False

      if response.status_code == 404:  # file not found in VirusTotal
        return True
      elif response.status_code == 200:
        logging.debug('[VT Plugin] File already available in VirusTotal.')
    elif self.auto_upload:
        logging.info('[VT Plugin] No API KEY is configured: unable to check file in VirusTotal.')
    return False

  def upload_file_to_VT(self):
    """Upload input file to VirusTotal."""

    if config.API_KEY:
      user_agent = 'IDA Pro VT Plugin upload - v' 
      user_agent += VT_IDA_PLUGIN_VERSION

      headers = {
          'User-Agent': user_agent,
          'x-apikey': config.API_KEY,
      }

      norm_path = os.path.normpath(self.input_file)
      file_path, file_name = os.path.split(norm_path)

      if os.path.isfile(self.input_file):
        logging.info('[VT Plugin] Uploading input file to VirusTotal.')
        url = 'https://www.virustotal.com/api/v3/files'
        files = {'file': (file_name, open(self.input_file, 'rb'))}

        try:
          response = requests.post(url, files=files, headers=headers)
        except:
          logging.error('[VT Plugin] Unable to connect to VirusTotal.com')

        if response.ok:
          logging.debug('[VT Plugin] Uploaded successfully.')
        else:
          logging.error('[VT Plugin] Upload failed.')
      else:
        logging.error('[VT Plugin] Uploading error: invalidad input file path.')
    else:
      logging.info('[VT Plugin] API Key not configured.')

  def run(self):
    if self.check_file_missing_in_VT() and self.auto_upload:
      self.upload_file_to_VT()


class VTpluginSetup(object):
  """Check and setup global parameters."""

  auto_upload = True
  vt_cfgfile = ''
  valid_setup = False
  file_path = ''
  file_name = ''
  file_hash = None
  vt_plugin_logger = None

  @staticmethod
  def show_warning():
    """Shows a popup window to ask for user consent in order to upload files."""

    warning_f = WarningForm()
    warning_f.Compile()
    change_config = warning_f.Execute()
    warning_f.Free()

    return change_config

  def read_config(self):
    """Read the user's configuration file."""

    logging.debug('[VT Plugin] Reading user config file: %s', self.vt_cfgfile)
    config_file = configparser.RawConfigParser()
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
      parser = configparser.ConfigParser()
      config_file = open(self.vt_cfgfile, 'w')
      parser.add_section('General')
      parser.set('General', 'auto_upload', str(self.auto_upload))
      parser.write(config_file)
      config_file.close()
    except:
      logging.error('[VT Plugin] Error while creating the user config file.')
      return False
    return True

  @staticmethod
  def __normalize(a, b):
    while len(a) > len(b):
      b = '0' + b
    while len(b) > len(a):
      a = '0' + a
    return a, b

  def __compare_versions(self, current, new):
    current_ver = current.split('.', 1)
    new_ver = new.split('.', 1)

    current_ver[0], new_ver[0] = self.__normalize(current_ver[0], new_ver[0])
    current_ver[1], new_ver[1] = self.__normalize(current_ver[1], new_ver[1])

    if (new_ver[0] > current_ver[0] or
        (new_ver[0] == current_ver[0] and new_ver[1] > current_ver[1])):
      return True
    return False

  def check_version(self):
    """Return True if there's an update available."""

    user_agent = 'IDA Pro VT Plugin checkversion - v' + VT_IDA_PLUGIN_VERSION
    headers = {
        'User-Agent': user_agent,
        'Accept': 'application/json'
    }
    url = 'https://raw.githubusercontent.com/VirusTotal/vt-ida-plugin/master/VERSION'

    try:
      response = requests.get(url, headers=headers)
    except:
      logging.error('[VT Plugin] Unable to check for updates.')
      return False

    if response.status_code == 200:
      version = response.text.rstrip('\n')
      if self.__compare_versions(VT_IDA_PLUGIN_VERSION, version):
        logging.debug('[VT Plugin] Version %s is available !', version)
        return True
    return False

  def __init__(self, cfgfile):
    self.vt_cfgfile = cfgfile
    self.file_path = idaapi.get_input_file_path()
    self.file_name = idc.get_root_filename()
    self.file_hash = calculate_hash(self.file_path)

    logging.info(
        '\n** VT Plugin for IDA Pro v%s (c) Google, 2025',
        VT_IDA_PLUGIN_VERSION
    )
    logging.info('** VirusTotal integration plugin for Hex-Ray\'s IDA Pro')
    logging.info('\n** This plugin provides two main features:')
    logging.info('** 1. Code Similarity Search (VTGrep):')
    logging.info('**    - Right-click in the Disassembly or Strings view to search for.')
    logging.info('**    - Exact bytes, similar code (ignoring addresses/constants), and similar functions.')
    logging.info('**    - Selected strings from the Strings window.')
    logging.info('** 2. Code Insight Notebook:')
    logging.info('**    - Get AI-powered analysis for any function (disassembled or decompiled).')
    logging.info('**    - Manage analyses in a persistent, dockable panel (View -> Open subviews -> VirusTotal).')
    logging.info('**    - Automatically add analysis summaries as comments to your functions.')
    logging.info('**    - Import/Export notebooks to share your work.')
    logging.info('\n** To get started with Code Insight, add your VT API key to config.py\n')


class Error(Exception):
  pass


class IncompatibleIdaVersion(Error):
  pass


def get_procname(arch_info):
  try:
    return arch_info.procname
  except AttributeError:
    pass
  try:
    return arch_info.procName
  except AttributeError:
    pass
  # IDA has changed the API, complain loudly and raise an exception.
  logging.error('[VT Plugin] Could not get procname from arch_info.')
  raise IncompatibleIdaVersion('[VT Plugin] Could not get procname from arch_info.')


class VTplugin(idaapi.plugin_t):
  """VirusTotal plugin interface for IDA Pro."""

  SEARCH_CODE_SUPPORTED = ['80286r', '80286p', '80386r', '80386p', '80486r',
                           '80486p', '80586r', '80586p', '80686p', 'k62', 'p2',
                           'p3', 'athlon', 'p4', 'metapc', 'ARM']
  SEARCH_STRICT_SUPPORTED = ['80286r', '80286p', '80386r', '80386p', '80486r',
                             '80486p', '80586r', '80586p', '80686p', 'k62',
                             'p2', 'p3', 'athlon', 'p4', 'metapc']

  flags = idaapi.PLUGIN_UNL
  comment = 'VirusTotal Plugin for IDA Pro'
  help = 'VirusTotal integration plugin for Hex-Ray\'s IDA Pro'
  wanted_name = 'VirusTotal'
  wanted_hotkey = ''
  vtpanel = None
  vtsetup = None

  def init(self):
    """Set up menu hooks and implements search methods."""

    valid_config = False
    self.menu = None
    config_file = os.path.join(idaapi.get_user_idadir(), 'virustotal.conf')
    self.vtsetup = VTpluginSetup(config_file)

    if self.vtsetup.check_version():
      ida_kernwin.info('VirusTotal\'s IDA Pro Plugin\nNew version available!')
      logging.info('[VT Plugin] There\'s a new version of this plugin!')
    else:
      logging.debug('[VT Plugin] No update available.')

    if os.path.exists(config_file):
      valid_config = self.vtsetup.read_config()
    else:
      answer = self.vtsetup.show_warning()
      if answer == 1:     # OK
        self.vtsetup.auto_upload = True
        valid_config = self.vtsetup.write_config()
      elif answer == 0:   # NO
        self.vtsetup.auto_upload = False
        valid_config = self.vtsetup.write_config()
      elif answer == -1:  # Cancel
        valid_config = False

    if valid_config:
      file_sample = CheckSample(self.vtsetup.auto_upload, self.vtsetup.file_path)
      file_sample.start()

      self.menu = Popups()
      self.menu.hook()
      
      if idaapi.IDA_SDK_VERSION >= 900:
        proc_name = ida_ida.inf_get_procname()
      else:
        arch_info = idaapi.get_inf_structure()
        proc_name = get_procname(arch_info)

      try:
        logging.debug('[VT Plugin] Processor detected by IDA: %s', proc_name)
        if (proc_name in self.SEARCH_STRICT_SUPPORTED) | (proc_name in self.SEARCH_CODE_SUPPORTED):
          VTGrepWildcards.register(self, 'Search for similar code')
          VTGrepWildCardsFunction.register(self, 'Search for similar functions')
          if len(config.API_KEY) > 0:
            CodeInsightASM.register(self, 'Ask Code Insight')
            CodeInsightDecompiled.register(self, 'Ask Code Insight')

          ### Register menu entry
          current_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
          file_icon = os.path.join(current_path,
                                   'ui',
                                   'resources',
                                   'vt_icon.png')
          vticon_data = open(file_icon, 'rb').read()
          vtmenu = idaapi.load_custom_icon(data=vticon_data)
          action_desc = idaapi.action_desc_t(
              'my:vtpanel',
              'VirusTotal',
              MenuVTPanel(),
              '',
              'Show VirusTotal panel with information about the current file',
              vtmenu)

          idaapi.register_action(action_desc)
          idaapi.attach_action_to_menu(
              'View/Open subviews/',
              'my:vtpanel',
              idaapi.SETMENU_APP)

          if proc_name in self.SEARCH_STRICT_SUPPORTED:
            VTGrepWildCardsStrict.register(self, 'Search for similar code (strict)')

        else:
          logging.info('\n - Processor detected: %s', get_procname(arch_info))
          logging.info(' - Searching for similar code is not available.')
        
        VTGrepBytes.register(self, 'Search for bytes')
        VTGrepStrings.register(self, 'Search for string')
      except:
        logging.error('[VT Plugin] Unable to register popups actions.')
    else:
      logging.info('[VT Plugin] Plugin disabled, restart IDA to proceed. ')
      ida_kernwin.warning('Plugin disabled, restart IDA to proceed.')
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
      ida_kernwin.warning('Point the cursor in an area beneath a function.')
      return

    search_vt = vtgrep.VTGrepSearch(
        addr_start=addr_func.start_ea,
        addr_end=addr_func.end_ea
        )
    search_vt.search(True, False)

  def query_codeinsight(self, *args, **kwargs):
    code_type = kwargs.get('code_type', None)
    current_address = idc.get_screen_ea()
    addr_func = idaapi.get_func(current_address)
  
    if not widget_panel.isVisible():
      widget_panel.Show("VirusTotal")
      idaapi.set_dock_pos('VirusTotal', '', idaapi.DP_RIGHT)

    try:
      faddr = addr_func.start_ea
    except:
      faddr = None

    if faddr:
      widget_panel.set_data(faddr,
                              fhash = self.vtsetup.file_hash,
                              ctype = code_type)
    else:
      logging.info('[VT Plugin] Current address doesn\'t belong to a function')


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