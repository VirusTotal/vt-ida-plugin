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

import binascii
import logging
from virustotal.vt_ida.disassembler import Disassembler
from virustotal.vt_ida.widgets import Widgets
import webbrowser

try:
  from urllib import quote
except ImportError:
  from urllib.parse import quote

 
class CodeInsightASM(object):

  _MIN_QUERY_SIZE = 100      # number of bytes
  _MAX_QUERY_SIZE = 4098   # Maximun length of a query string

  def __init__(self, *args, **kwargs):
    self.string_searching = kwargs.get('string', False)
    if self.string_searching:
      self.string_searching = self.string_searching.encode('utf-8')
    self.addr_start = kwargs.get('addr_start', 0)
    self.addr_end = kwargs.get('addr_end', 0)


  def __create_query(self):
    """Returns a buffer containing all the bytes of the instructions selected.

      If there are instructions that contain offsets or memory addresses,
    their operands will be wildcarded.

    Args:
      wildcards: True -> wildcards will be applied, False -> raw bytes
      strict: True -> all constants will be wildcarded
    Returns:
      Bytes: all the bytes belonging to the current selected instructions.

    """

    current = self.addr_start
    str_buf = ''

    # Check if current selection is in a valid range
    if not Disassembler.valid_address_range(self.addr_start, self.addr_end):
      logging.error('[CodeInsight] Select a valid function.')
      return None
    elif not Disassembler.valid_range_size(
        self.addr_start,
        self.addr_end,
        self._MAX_QUERY_SIZE
        ):
      logging.error('[CodeInsight] The function selected is too large.')
      return None
    else:  # Selected area is valid
      while current < self.addr_end:
        new_instr = Disassembler.get_ASM_string(current)
        if new_instr == 0:
          break  # Unable to disassemble current address
        else:
          str_buf += '\n'
          str_buf += new_instr
        current = Disassembler.next_address(current)
    if str_buf:
      return str_buf
    else:
      return None
 
  def askCI(self):
    str_buf = self.__create_query()
  
    # After creating the search string, checks if new size is valid
    if str_buf is None:
      logging.error('[CodeInsight] Final query length is too long.')
      Widgets.show_warning('Invalid query length or function selected.')
    else:
      len_query = len(str_buf)

      if len_query and self._MIN_QUERY_SIZE >= len_query:
        logging.error('[CodeInsight] The query produced is too short.')
        Widgets.show_warning('The query produced is too short.')
      elif len_query and len_query > self._MAX_QUERY_SIZE:
        logging.error('[CodeInsight] The query produced is too long.')
        Widgets.show_warning('The query produced is too long.')
      else:
        print(str_buf)
