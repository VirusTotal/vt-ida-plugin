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

import logging
import requests
from virustotal import config
from virustotal.vt_ida.disassembler import Disassembler
import threading
import json
import base64
from virustotal.ci_notebook import CI_Notebook
from virustotal.vt_ida.vtwidgets import VTWidgets

try:
  from urllib import quote
except ImportError:
  from urllib.parse import quote

CI_DECOMPILED= 'decompiled'
CI_DISASSEMBLED = 'disassembled'
ci_notebook = CI_Notebook()

class QueryCodeInsight(threading.Thread):
  """A thread to query the VirusTotal Code Insight API."""
  use_codetype = None
  encoded_src = None
  _return = None
  _error_msg = None
    
  def __init__(self, *args, **kwargs):
    """Initializes the QueryCodeInsight thread.

    Args:
      *args: Variable length argument list (not used).
      **kwargs: Arbitrary keyword arguments.
        use_codetype (str): The type of code being sent ('decompiled' or
          'disassembled').
        code (str): The source code to analyze.
    """
    self.use_codetype = kwargs.get('use_codetype', '')
    self.code = kwargs.get('code', '')

    if self.use_codetype: 
      logging.debug('[VT Plugin] CodeInsight using src code type: %s', self.use_codetype)

    if self.code == '':
      logging.error('[VT Plugin] No proper query created for CodeInsight')
      exit()

    threading.Thread.__init__(self)

  def get_encoded_src(self):
    """Returns the base64 encoded source code of the query.

    Returns:
      str: The base64 encoded source code.
    """
    return self.encoded_src

  def get_error_msg(self):
    """Returns the error message if the query failed.

    Returns:
      str: The error message, or None if there was no error.
    """
    return self._error_msg

  def _process_request(self, query):
    """Encodes the query string in base64.

    Args:
      query (str): The code to be sent to Code Insight.

    Returns:
      str: The base64 encoded query.
    """
    ci_request = base64.urlsafe_b64encode(query.encode('utf-8'))
    self.encoded_src = ci_request.decode('ascii')
    return self.encoded_src
   
  def _process_output(self, response):
    """Processes the JSON response from the Code Insight API.

    It decodes the response, checks for errors, and extracts the answer.

    Args:
      response (str): The JSON response from the API as a string.

    Returns:
      str: The decoded answer from Code Insight, or None if an error occurred.
    """
    decoded_str = ''
    json_data = json.loads(response)
    answer = json_data['data']
   
    if 'error' in answer:
      error_response = json.loads(answer['error'])
      self._error_msg = error_response['message']

      logging.debug('[VT Plugin] ERROR message: %s', error_response['message'])
      if 'not_parsed_output' in error_response:
        logging.debug('[VT Plugin] ERROR output: %s', error_response['not_parsed_output'])
      elif 'original_message' in error_response:  
        logging.debug('[VT Plugin] ERROR output: %s', error_response['original_message'])        
      return None
    
    try:
      decoded_str = base64.urlsafe_b64decode(answer)
    except: 
      logging.debug('[VT Plugin] ERROR decoding CodeInsight response: %s', response)  
    
    return decoded_str
  
  def run(self):
    """The main execution method for the thread.

    Constructs and sends a request to the Code Insight API and processes the
    response. The result is stored in self._return and any error message in
    self._error_msg.
    """
    global CI_DISASSEMBLED, CI_DECOMPILED
    global ci_notebook
 
    if len(config.API_KEY) == 0:
      logging.error('[VT Plugin] VirusTotal\'s API_KEY not configured or invalid.')
      VTWidgets.show_warning('A VirusTotal API Key has not been configured,\nplease indicate your API KEY in the "config.py" file.')
      return

    API_URL = 'https://www.virustotal.com'
    endpoint = 'api/v3/codeinsights/analyse-binary'
    headers_apiv3 = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'x-apikey': config.API_KEY}  

    payload = {
        'code': self._process_request(self.code),
      }
        
    if self.use_codetype == CI_DECOMPILED:
      payload['code_type'] = self.use_codetype
    else:
      payload['code_type'] = CI_DISASSEMBLED

    if ci_notebook.get_total():
      history = []

      for key in ci_notebook.get_functions():
        page= {}

        summary = ci_notebook.get_page(key)['summary']
        description = ci_notebook.get_page(key)['description']
        
        expected_summary = ci_notebook.get_page(key)['expected_summary']
        expected_description = ci_notebook.get_page(key)['expected_description']
        
        if expected_summary:
          summary = expected_summary
        
        if expected_description:
          description = expected_description
        
        encoded_response = CI_Notebook.encode_response(summary, description)
        page['request'] = ci_notebook.get_page(key)['b64code']
        page['response'] = encoded_response
        history.append(page)

      payload['history'] = history
      
    logging.debug('[VT Plugin] Sending request to CodeInsight')
    logging.debug('[VT Plugin] Payload: %s', payload)

    try:
      response = requests.post(f'{API_URL}/{endpoint}', json = {'data': payload}, headers=headers_apiv3)
    except:
      logging.debug('[VT Plugin] ERROR: unable to connect to CodeInsight')
      self._error_msg = 'ERROR: unable to connect to CodeInsight'
      return

    if response.status_code == 200:
      self._return = self._process_output(response.text)
    else:
      logging.debug('[VT Plugin] ERROR connecting CodeInsight: %s', response.text)
      self._error_msg = response.text
  
  def join(self, *args):
    """Waits for the thread to complete and returns the result.

    Overrides `threading.Thread.join` to return the value from the API call.

    Args:
      *args: Variable length argument list passed to `threading.Thread.join`.

    Returns:
      The result from the Code Insight query, or None if an error occurred.
    """
    threading.Thread.join(self, *args)
    return self._return


class CodeInsightASM(object):
  """Handles Code Insight queries for assembly code."""
  def __init__(self, *args, **kwargs):
    """Initializes the CodeInsightASM object.

    Args:
      *args: Variable length argument list (not used).
      **kwargs: Arbitrary keyword arguments.
        addr_start (int): The starting memory address for disassembly.
        addr_end (int): The ending memory address for disassembly.
    """
    self._MIN_QUERY_SIZE = 40      # number of bytes
    self._MAX_QUERY_SIZE = 4096    # Maximun length of a query string

    self._addr_start = kwargs.get('addr_start', 0)
    self._addr_end = kwargs.get('addr_end', 0)
    self.code_src = None
    self.encoded_src = None
    self.encoded_response = None
    self.error_msg = None

  def get_src(self):
    """Returns the raw assembly source code generated for the query.

    Returns:
      str: The assembly source code.
    """
    return self.code_src

  def get_encoded_src(self):
    """Returns the base64 encoded assembly source code of the query.

    Returns:
      str: The base64 encoded source code.
    """
    return self.encoded_src

  def get_encoded_response(self):
    """Returns the base64 encoded response from a previous query.

    Note: This seems to be intended for storing the response, but
    `self.encoded_response` is never set.

    Returns:
      The value of self.encoded_response, which is initialized to None.
    """
    return self.encoded_response
  
  def _create_query(self):
    """Creates an assembly query string from the selected address range.

    Gathers disassembly from the start to the end address, including a
    function header and footer.

    Returns:
      str: A string containing the formatted assembly code for the query,
           or None if the address range is invalid or too large.
    """
    current = self._addr_start
    str_buf = ''
    disasm_engine = Disassembler()

    # Check if current selection is in a valid range
    if not disasm_engine.valid_address_range(self._addr_start, self._addr_end):
      logging.error('[CodeInsight] Select a valid function.')
      return None
    elif not disasm_engine.valid_range_size(
        self._addr_start,
        self._addr_end,
        self._MAX_QUERY_SIZE
        ):
      logging.error('[CodeInsight] The function selected is too large.')
      return None
    
    # Selected area is valid

    while current < self._addr_end:
      new_instr = disasm_engine.get_ASM_string(current)
      if new_instr == 0:
        break  # Unable to disassemble current address
      else:
        str_buf += '\n'
        str_buf += hex(current)
        str_buf += ' '
        str_buf += new_instr
      current = disasm_engine.next_address(current)

    if str_buf:
      header = disasm_engine.get_ASM_function_header(self._addr_start)
      footer = disasm_engine.get_ASM_function_footer(self._addr_start)
      return_str = '{}\n{}\n{}\n'.format(header, str_buf, footer)
      return return_str
    else:
      return None

  def get_error_msg(self):
    """Returns the error message if the query failed.

    Returns:
      str: The error message, or None if there was no error.
    """
    return self.error_msg

  def askCI(self, *args, **kwargs):
    """Sends an assembly code query to Code Insight.

    It creates the query, validates its size, runs the query in a separate
    thread, and processes the response.

    Args:
      *args: Variable length argument list (not used).
      **kwargs: Arbitrary keyword arguments.
        use_codetype (str): The type of code being sent.

    Returns:
      dict: The parsed JSON response from Code Insight, or None if an error
            occurred.
    """
    global widget_panel

    codetype = kwargs.get('use_codetype', '')
    self.code_src = self._create_query()

    # After creating the search string, checks if new size is valid
    if self.code_src is None:
      logging.error('[CodeInsight] Final query length is too long.')
      VTWidgets.show_warning('Invalid query length or function selected.')
      return None

    len_query = len(self.code_src)
    logging.debug('[CodeInsight] Final query length is: %d', len_query)
    if len_query and self._MIN_QUERY_SIZE >= len_query:
      logging.error('[CodeInsight] The query produced is too short.')
      VTWidgets.show_warning('The query produced is too short.')
      return None

    logging.debug('[CodeInsight] Query created for CodeInsight')
    ci = QueryCodeInsight(code=self.code_src, 
                          use_codetype=codetype)
    ci.start()
    json_str = ci.join()

    self.encoded_src = ci.get_encoded_src()
        
    if json_str:
      try:
        return_msg = json.loads(json_str)
      except:
        logging.debug('[CodeInsight] Error processing the returned json file.')
      return return_msg
    else:
      self.error_msg = ci.get_error_msg()
    
    return None 


class CodeInsightDecompiled(object):
  """Handles Code Insight queries for decompiled C-like code."""
  def __init__(self, *args, **kwargs):
    """Initializes the CodeInsightDecompiled object.

    Args:
      *args: Variable length argument list (not used).
      **kwargs: Arbitrary keyword arguments.
        code_src (str): The decompiled source code to analyze.
    """
    self._MIN_QUERY_SIZE = 40      # number of bytes
    self.code_src = str(kwargs.get('code_src', ''))
    self.encoded_src = None

    if self.code_src:
      self.code_src += '\n'
    
  def get_src(self):
    """Returns the raw decompiled source code for the query.

    Returns:
      str: The decompiled source code.
    """
    return self.code_src

  def get_error_msg(self):
    """Returns the error message if the query failed.

    Returns:
      str: The error message, or None if there was no error.
    """
    return self.error_msg
  
  def get_encoded_src(self):
    """Returns the base64 encoded decompiled source code of the query.

    Returns:
      str: The base64 encoded source code.
    """
    return self.encoded_src
  
  def askCI(self, *args, **kwargs):
    """Sends a decompiled code query to Code Insight.

    It validates the code size, runs the query in a separate thread, and
    processes the response.

    Args:
      *args: Variable length argument list (not used).
      **kwargs: Arbitrary keyword arguments (not used).

    Returns:
      dict: The parsed JSON response from Code Insight, or None if an error
            occurred.
    """
    global widget_panel

    # After creating the search string, checks if new size is valid
    if self.code_src is None:
      logging.error('[CodeInsight] Final query length is too long.')
      VTWidgets.show_warning('Invalid query length or function selected.')
      return None

    len_query = len(self.code_src)
    logging.debug('[CodeInsight] Final query length is: %d', len_query)
    if len_query and self._MIN_QUERY_SIZE >= len_query:
      logging.error('[CodeInsight] The query produced is too short.')
      VTWidgets.show_warning('The query produced is too short.')
      return None
    
    logging.debug('[VT Plugin] Query created for CodeInsight')
    ci = QueryCodeInsight(code=self.code_src, use_codetype=CI_DECOMPILED)
    ci.start()
    json_str = ci.join()

    self.encoded_src = ci.get_encoded_src()
    
    if json_str:
      return json.loads(json_str)
    else:
      self.error_msg = ci.get_error_msg()
    
    return None
