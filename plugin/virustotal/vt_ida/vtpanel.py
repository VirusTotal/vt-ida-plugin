# Copyright 2020 Google Inc. All Rights Reserved.
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
import ida_kernwin
import ida_hexrays
import idc
from idaapi import PluginForm
from virustotal.vt_ida.ui.panel import Ui_panelUI
from virustotal import codeinsight
from virustotal.codeinsight import ci_notebook
from virustotal.vt_ida.vtwidgets import VTWidgets
import logging
import base64
import textwrap
import json


class VTPanel(PluginForm):
  """A PluginForm that displays VirusTotal Code Insight analysis within IDA.

  This panel allows users to request analysis for functions, view the results,
  edit them, and manage a "notebook" of analyzed functions.
  """
  visible = False
  summary = None
  description = None
  expected_summary = None
  expected_description = None
  faddr = None
  fname = None
  ctype = None
  code_src = None
  encoded_src = None

  ci_search = None
  fhash = None
 

  def OnCreate(self, form):
    """Called by IDA when the form is created.

    Initializes the UI, connects widget signals to their corresponding slots,
    and sets the initial state of the UI elements.

    Args:
      form: The TForm object created by IDA.
    """
   
    self.parent = self.FormToPyQtWidget(form)
    self._populateForm()
    self._panel.pb_accept.setEnabled(False)
    self._panel.pb_discard.setEnabled(False)
    self._panel.cb_faddress.setEnabled(False)

    self._panel.te_ci_summary.textChanged.connect(self._summary_updated)
    self._panel.te_ci_description.textChanged.connect(self._description_updated)
    self._panel.cb_faddress.currentIndexChanged.connect(self._faddress_selected)   
    self._panel.pb_accept.clicked.connect(self._accept_analysis)
    self._panel.pb_discard.clicked.connect(self._discard_analysis)
    self._panel.pb_go.clicked.connect(self._go)
    self._panel.pb_autocomment.clicked.connect(self._auto_comment)
    self._panel.pb_askCI.clicked.connect(self.askCI_EA)
    self._panel.pb_refresh.clicked.connect(self._refreshCI)
    self._panel.pb_load.clicked.connect(self._load)
    self._panel.pb_export.clicked.connect(self._export)

  def _go(self):
    """Jumps the IDA disassembly view to the address of the current function."""
    if self.faddr:
      if not ida_kernwin.jumpto(self.faddr):
        logging.info('[VT Plugin] Functions address can\'t be found: %s', hex(self.faddr))

  def _load(self):
    """Handles importing a Code Insight notebook from a JSON file.

    Prompts the user to select a file. If a file is selected, it replaces
    the current notebook with the data from the file and updates the UI.
    Warns the user if a notebook is already loaded, as this action will
    overwrite it.
    """
    global ci_notebook

    if self._panel.cb_faddress.count() != 0:       
      msg = """Importing a new CodeInsight Notebook

The current notebook will be replaced with a new one.

"""
      proceed_import = idaapi.ask_form(msg)
    else:
      proceed_import = 1

    if proceed_import == 1:  # Yes

      filename = ida_kernwin.ask_file(0, "*.json", "Select file to import:")
      
      if filename:
        logging.info('[VT Plugin] Importing file: %s', filename)

        try:
          logging.debug('[VT Plugin] Loading CodeInsight Notebook file: %s', filename)
          with open(filename, 'r', encoding='utf-8') as f:
            imported_json = json.load(f)
        except:
            logging.error('[VT Plugin] ERROR importing file: %s', filename)      

        ci_notebook.import_data(imported_json)
        self._read_notebook()
        self.clean_view()
      else:
        logging.debug('[VT Plugin] No file selected to import CI Notebook')
    
    else:  # Cancelled
        logging.debug('[VT Plugin] User canceled the import of a new notebook')

  def _export(self):
    """Exports the current Code Insight notebook to a JSON file.

    Prompts the user for a filename and saves the entire contents of the
    current notebook.
    """
    global ci_notebook

    filename = ida_kernwin.ask_file(1, "*.json", "Enter name of the file:")
    logging.info('[VT Plugin] File will be saved in: %s', filename)

    try:
      logging.debug('[VT Plugin] Exporting CodeInsight Notebook to file: %s', filename)
      with open(filename, 'w', encoding='utf-8') as f:
        json.dump(ci_notebook.show_pages(), f)
    except:
        logging.error('[VT Plugin] ERROR saving file: %s', filename)


  def askCI_EA(self):
    """Initiates a Code Insight query for the function at the current cursor
    position.

    Clears the view and then triggers a new analysis for the function under the
    current effective address (EA) in IDA's disassembly view.

    """

    current_address = idc.get_screen_ea()
    addr_func = idaapi.get_func(current_address) 

    if not addr_func:
      logging.error('[VT Plugin] Current address doesn\'t belong to a function')
      VTWidgets.show_warning('The cursor must be within a function.')
      return

    self.clean_view()

    # Determine the active window type to set the correct code type for the query.
    widget_ida = idaapi.get_current_widget()
    widget_ida_type = idaapi.get_widget_type(widget_ida)

    if widget_ida_type == idaapi.BWN_DISASM:
        code_type = codeinsight.CI_DISASSEMBLED
    elif widget_ida_type == idaapi.BWN_PSEUDOCODE:
        code_type = codeinsight.CI_DECOMPILED
    else:
        # If the active window is neither, we can't proceed.
        logging.warning('[VT Plugin] "Ask CI" can only be used from the Disassembly or Pseudocode views.')
        VTWidgets.show_warning('This functionality can only be used from the\nDisassembly or Pseudocode views.')
        return

    self.set_data(faddr = addr_func.start_ea,
                   ctype = code_type)

  def _askCI_Disassembled(self, faddr=None):
    """Performs a Code Insight query using the disassembly of a function.

    It creates a `CodeInsightASM` object, sends the request, and processes
    the response, updating the panel's internal state with the results.

    Args:
      faddr (int, optional): The starting address of the function to analyze.
    """
    addr_func = idaapi.get_func(faddr)
    if not addr_func:    
      logging.error('[VT Plugin] Current address doesn\'t belong to a function')
      ida_kernwin.warning('Point the cursor in an area beneath a function.')
      return
    
    self.ci_search = codeinsight.CodeInsightASM(
        addr_start = addr_func.start_ea,
        addr_end = addr_func.end_ea,
        )
    self.ci_report = self.ci_search.askCI(use_codetype = codeinsight.CI_DISASSEMBLED)

    try:
      self.summary = self.ci_report['summary']
      self.description = self.ci_report['description']
    except:
      logging.error('[VT Plugin] Invalid answer received from CodeInsight')
      self.summary = None
      self.description= None
      return

    self.faddr = faddr
    self.fname = idc.get_func_name(addr_func.start_ea)
    self.ctype = codeinsight.CI_DISASSEMBLED
    self.encoded_src = self.ci_search.get_encoded_src()
    self.code_src =  self.ci_search.get_src()

  def _askCI_Decompiled(self, faddr=None):
    """Performs a Code Insight query using the decompiled C-like code of a
    function.

    It uses `ida_hexrays.decompile` to get the source, creates a
    `CodeInsightDecompiled` object, sends the request, and updates the panel's
    internal state with the results.

    Args:
      faddr (int, optional): The starting address of the function to analyze.
    """
    addr_func = idaapi.get_func(faddr)

    if not addr_func:
      logging.error('[VT Plugin] Current address doesn\'t belong to a function')
      ida_kernwin.warning('Point the cursor in an area beneath a function.')
      return
    
    ci_src = ida_hexrays.decompile(faddr)
    #VTWidgets.show_wait('NODELAY\nSending request to CodeInsight...')
    self.ci_search = codeinsight.CodeInsightDecompiled(code_src = ci_src)
    self.ci_report = self.ci_search.askCI(use_codetype = codeinsight.CI_DECOMPILED)

    #VTWidgets.hide_wait()

    try:
      self.summary = self.ci_report['summary']
      self.description = self.ci_report['description']
    except:
      logging.error('[VT Plugin] Invalid answer received from CodeInsight')
      return
    
    # setting up default showed data
    self.faddr = faddr
    self.fname = idc.get_func_name(addr_func.start_ea)
    self.ctype = codeinsight.CI_DECOMPILED
    self.encoded_src = self.ci_search.get_encoded_src()    
    self.code_src =  self.ci_search.get_src()

  def _refreshCI(self):   
    """Refreshes the Code Insight analysis for the currently viewed function."""
    self.set_data(self.faddr, self.ctype)

  def _auto_comment(self): 
    """Adds or updates IDA function comments for all functions in the notebook.

    Iterates through each function in the `ci_notebook`. For each function, it
    takes the 'expected_summary' (if available) or the 'summary' and adds it
    as a repeatable function comment in IDA.

    If a Code Insight comment block (marked with `[CodeInsight start]` and
    `[CodeInsight end]`) already exists, it is replaced. Otherwise, the new
    comment is appended to any existing comments.
    """

    global ci_notebook

    n_func = ci_notebook.get_total()

    if n_func > 0:
      logging.debug('[VT Plugin] Adding/updating comments for %d functions', n_func)
      for key_str in ci_notebook.get_functions():
        key = int(key_str, 16)  # Convert hex string key to integer address.
        page = ci_notebook.get_page(key_str)

        # Determine the summary to be used for the comment.
        if page.get('expected_summary'):
          summary = page['expected_summary']
        else:
          summary = page.get('summary', '')

        # Skip if there's no summary to add.
        if not summary:
          logging.debug('[VT Plugin] No summary for function %s, skipping.', key_str)
          continue
        
        # Prepare the new comment block with markers.
        wrapped_summary = textwrap.fill(summary, width=80)
        new_comment_block = "[CodeInsight start]\n {} \n[CodeInsight end]".format(wrapped_summary)
        
        # The plugin will consistently work with the "repeatable" comment (type 0).
        current_comment = idc.get_func_cmt(key, 0) or ""

        start_marker = "[CodeInsight start]"
        end_marker = "[CodeInsight end]"
        start_pos = current_comment.find(start_marker)

        final_comment = ""
        if start_pos != -1:
          # An old CodeInsight comment exists, so replace it.
          logging.debug('[VT Plugin] Updating existing CodeInsight comment for %s.', key_str)
          end_pos = current_comment.find(end_marker, start_pos)
          if end_pos != -1:
            # Preserve text before and after the old block.
            before_block = current_comment[:start_pos]
            after_block = current_comment[end_pos + len(end_marker):]
            # Reconstruct the comment to ensure clean separation.
            final_comment = before_block.rstrip() + '\n' + new_comment_block + '\n' + after_block.lstrip()
          else:
            # Malformed comment (start without end). Append new block to be safe.
            logging.warning('[VT Plugin] Malformed comment in %s. Appending.', key_str)
            final_comment = current_comment + '\n\n' + new_comment_block
        else:
          # No old CodeInsight comment. Append the new block to existing comments.
          logging.debug('[VT Plugin] Adding new CodeInsight comment for %s.', key_str)
          if current_comment:
            final_comment = current_comment + '\n\n' + new_comment_block
          else:
            final_comment = new_comment_block
            
        # Set the new repeatable comment, stripping excess whitespace.
        idc.set_func_cmt(key, final_comment.strip(), 0)

      ida_kernwin.info("Comments updated for {} function(s).".format(n_func))
      self._panel.pb_autocomment.setEnabled(False)


  def _summary_updated(self):
    """Slot connected to the summary text edit's `textChanged` signal.

    It detects if the user has modified the summary text provided by Code
    Insight. If so, it enables the 'Accept' and 'Discard' buttons and stores
    the new text in `self.expected_summary`.
    """
    new_summary = self._panel.te_ci_summary.toPlainText()
    if not (self.summary == new_summary):
      self._panel.pb_accept.setEnabled(True)
      self._panel.pb_discard.setEnabled(True)
      self.expected_summary = self._panel.te_ci_summary.toPlainText()

  def _description_updated(self):
    """Slot connected to the description text edit's `textChanged` signal.

    It detects if the user has modified the description text provided by Code
    Insight. If so, it enables the 'Accept' and 'Discard' buttons and stores
    the new text in `self.expected_description`.
    """
    new_description = self._panel.te_ci_description.toPlainText()
    if not (self.description == new_description):
      self._panel.pb_accept.setEnabled(True)
      self._panel.pb_discard.setEnabled(True)
      self.expected_description = self._panel.te_ci_description.toPlainText()

  def _faddress_selected(self, index):
    """Slot connected to the function address combo box's
    `currentIndexChanged` signal.

    When a user selects a function from the dropdown, this method loads the
    corresponding analysis from the `ci_notebook` and updates the entire view.

    Args:
      index (int): The index of the item selected in the combo box.
    """
    selected_item = self._panel.cb_faddress.itemText(index)

    if selected_item != "":
      logging.debug('[VT Plugin] Function selected: %s', selected_item)
      self.clean_view()

      if selected_item:
        selected_analysis = ci_notebook.get_page(selected_item)
        self._panel.pb_accept.setEnabled(False)

        if selected_analysis: 
          logging.debug("[VT Plugin] Selected function %s from CI_Notebook: %s", 
                        selected_item, 
                        selected_analysis)
          self.faddr = int(selected_item,16)
      
          if 'expected_summary' in selected_analysis:
            self.expected_summary = selected_analysis['expected_summary']

          if 'expected_description' in selected_analysis:
            self.expected_description = selected_analysis['expected_description']

          self.summary = selected_analysis['summary']
          self.description = selected_analysis['description']
          self.fname = selected_analysis['func_name']
          self.ctype = selected_analysis['code_type']
          self.encoded_src = selected_analysis['b64code']
          code = base64.b64decode(self.encoded_src)
          self.code_src = code.decode('ascii')   
          
          self._update_view()
          self._panel.cb_faddress.setCurrentIndex(0)
          self._panel.pb_discard.setEnabled(True)
          self._panel.pb_refresh.setEnabled(True)
          self._panel.pb_go.setEnabled(True)
        else:
          self._panel.pb_discard.setEnabled(False)

  def _populateForm(self):
    """Initializes the UI from the Qt-generated `Ui_panelUI` class."""
    self._panel = Ui_panelUI()
    self._panel.setupUi(self.parent)

  def clean_view(self):
    """Clears all data from the UI panel and resets internal state variables.

    This is used to prepare the panel for a new query or when discarding an
    analysis. It also resets the enabled state of various buttons.
    """

    self._panel.te_ci_summary.clear()
    self._panel.te_ci_description.clear()
    self._panel.le_codetype.clear()
    self._panel.le_fname.clear()
    self._panel.le_faddress.clear()
    self.summary = None
    self.description = None
    self.expected_summary = None
    self.expected_description = None
    self.faddr = None
    self.fname = None
    self.ctype = None
    self.code_src = None
    self.encoded_src = None
    self.ci_report = None
    self.ci_search = None

    # Nothing selected yet
    self._panel.pb_refresh.setEnabled(False)
    self._panel.pb_accept.setEnabled(False)
    self._panel.pb_discard.setEnabled(False)
    self._panel.pb_refresh.setEnabled(False)
    self._panel.pb_go.setEnabled(False)

    if self._panel.cb_faddress.count() <= 1:
      # We have some functions in the functions list
      self._panel.pb_export.setEnabled(False)
      self._panel.pb_autocomment.setEnabled(False)
      self._panel.cb_faddress.setEnabled(False)
    else:
      self._panel.pb_export.setEnabled(True)
      self._panel.pb_autocomment.setEnabled(True)
      self._panel.cb_faddress.setEnabled(True)


  def _discard_analysis(self):
    """Discards the analysis for the currently displayed function.

    Removes the function's page from the `ci_notebook`, removes its entry
    from the function dropdown, and cleans the view. If other functions remain
    in the notebook, it displays the next one.
    """
    global ci_notebook

    # Check if current function address is in the CodeInsight Notebook
    if ci_notebook.get_page(hex(self.faddr)):
      logging.debug('[VT Plugin] Discarding analysis for %s', hex(self.faddr))
      ci_notebook.discard_page(hex(self.faddr))
      self._panel.cb_faddress.removeItem(self._panel.cb_faddress.findText(hex(self.faddr)))

    self.clean_view()

    self._panel.pb_accept.setEnabled(False)
    self._panel.pb_discard.setEnabled(False)
    self._panel.pb_refresh.setEnabled(False)

    if self._panel.cb_faddress.count() > 1:
      # Show next page in the notebook
      self._faddress_selected(self._panel.cb_faddress.currentIndex())

  def _update_view(self):
    """Populates the UI widgets with the current function's analysis data.

    It sets the text for summary, description, code type, function name, and
    address, using the user-edited "expected" values if they exist.
    """
    # Updating display

    if self.expected_summary:
      self._panel.te_ci_summary.setText(self.expected_summary)
    else:
      self._panel.te_ci_summary.setText(self.summary)
    
    if self.expected_description:
      self._panel.te_ci_description.setText(self.expected_description)   
    else:
      self._panel.te_ci_description.setText(self.description)
    
    self._panel.le_codetype.setText(self.ctype)
    self._panel.le_fname.setText(self.fname)
    self._panel.le_faddress.setText(hex(self.faddr))
    
  def _accept_analysis(self):
    """Saves the current analysis to the Code Insight notebook.

    This is called when the user clicks the 'Accept' button. It takes the
    current data (including any user edits) and adds or updates a page in the
    `ci_notebook`. It also updates the UI state accordingly.
    """
    global ci_notebook   
    
    ci_notebook.add_page(func_name = self.fname, 
                          func_addr = hex(self.faddr), 
                          code_type = self.ctype,
                          b64code = self.encoded_src, 
                          summary = self.summary,
                          description = self.description,
                          expected_summary = self.expected_summary,
                          expected_description = self.expected_description
                          )

    list_faddress = [self._panel.cb_faddress.itemText(i) for i in range(self._panel.cb_faddress.count())]   
    
    if self._panel.cb_faddress.count() == 0:
      self._panel.cb_faddress.addItem("")

    if hex(self.faddr) not in list_faddress:
      logging.debug('[VT Plugin] Including current function in the notebook: %s', hex(self.faddr))
      self._panel.cb_faddress.addItem(hex(self.faddr))

    self._panel.pb_discard.setEnabled(True)
    self._panel.cb_faddress.setEnabled(True)
    self._panel.pb_export.setEnabled(True)
    self._panel.pb_autocomment.setEnabled(True)
    self._panel.pb_accept.setEnabled(False)
    self._panel.pb_go.setEnabled(True)
    

  def _read_notebook(self):
    """Reads the global `ci_notebook` and populates the function address
    combo box.

    This is used when loading a notebook from a file to make all its analyzed
    functions available in the dropdown list.
    """
    global ci_notebook
    
    logging.debug('[VT Plugin] Importing notebook.')

    # Clean the list bar erasing any previous content.
    self._panel.cb_faddress.clear()

    if ci_notebook:

      # Add functions to the list bar
      list_faddress = [self._panel.cb_faddress.itemText(i) for i in range(self._panel.cb_faddress.count())]   

      if self._panel.cb_faddress.count() == 0:
        self._panel.cb_faddress.addItem("")

      # Iterate over every function in the Notebook
      for address in ci_notebook.get_functions():
        if address not in list_faddress:
          self._panel.cb_faddress.addItem(address)


  def set_data(self, faddr=None, fhash=None, ctype=None):
    """The main entry point to populate the panel with data.

    If `faddr` is provided, it initiates a new Code Insight query for that
    function address.

    If `faddr` is not provided, it checks if the notebook contains any data
    (e.g., after closing and reopening the panel) and loads it.

    Args:
      faddr (int, optional): The starting address of the function to analyze.
      fhash (str, optional): The hash of the file being analyzed (not currently
        used for queries).
      ctype (str, optional): The type of code to analyze ('decompiled' or
        'disassembled'). Defaults to 'disassembled'.
    """
    # Entry point function
    global ci_notebook
    
    if faddr:
      logging.debug('[VT Plugin] Creating VTPanel, function: %s', hex(faddr))

      if ctype == codeinsight.CI_DECOMPILED:
        self._askCI_Decompiled(faddr)
      else:  # Disassembled function selected or null ctype
        self._askCI_Disassembled(faddr)

      if self.summary:        
        # Updating display
        self._update_view()
        self.fhash = fhash
        self._panel.pb_accept.setEnabled(True) 
        self._panel.pb_refresh.setEnabled(True)
        return
      
    else:
      if ci_notebook.get_total():
        # If the list of functions is empty but there are functions in the CI Notebook 
        # it means that the user closed the VTPanel widget. We need to load all the 
        # functions in the notebook and import them into the current panel.

        self._panel.cb_faddress.addItem("")

        for address in ci_notebook.get_functions():
          logging.debug('[VT Plugin] Adding function to the list bar: %s', address)
          self._panel.cb_faddress.addItem(address)
      else:
        logging.debug('[VT Plugin] Creating an empty VTPanel')
    
    self.clean_view()
  

  def OnClose(self, form):
    """Called by IDA when the plugin form is closed.

    Args:
      form: The TForm object being closed.
    """
    self.clean_view()
    self.visible = False
    pass
  
  def isVisible(self):
    """Returns the visibility state of the panel.

    Returns:
      bool: True if the panel is currently visible, False otherwise.
    """
    return self.visible

  def Show(self, title):
    """Creates the form or shows it if it already exists."""

    flags = (
              idaapi.PluginForm.WOPN_TAB
              | idaapi.PluginForm.WOPN_MENU
              | idaapi.PluginForm.WOPN_PERSIST
    )

    vtpanel_window = PluginForm.Show(self,
                           title,
                           options = flags)
    self.visible = True
    
    return vtpanel_window
