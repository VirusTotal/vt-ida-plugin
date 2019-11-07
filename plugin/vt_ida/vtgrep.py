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
import idautils
import idc
import logging
import urllib
import webbrowser


class Bytes(object):
  """Class that represents a slice of bytes in a search query."""

  bytes_stream = ''

  def __init__(self, buf):
    self.bytes_stream = buf

  def append(self, qslice):
    if not isinstance(qslice, Bytes):
      self.bytes_stream += qslice
    else:
      self.bytes_stream += qslice.get()

  def get(self):
    return self.bytes_stream

  def len(self):
    return len(self.bytes_stream)

  def combine(self, next_object):
    if next_object:
      if isinstance(next_object, Bytes):
        self.append(next_object)
        return self
      else:
        if self.len() < 8:
          wcs_stream = '?' * self.len()
          next_object.append(wcs_stream)
          return next_object
        else: return -1
    else:
      if self.len() < 8:
        return self
      else: return -1


class WildCards(object):
  """Class that represents a slice of wildcards in a search query."""

  wcs_stream = ''
  packed = False

  def __init__(self, buf):
    self.wcs_stream = buf
    self.pack()

  def append(self, qslice):
    # slice can be a WildCards instance or a string of wildcards
    if not self.packed and not isinstance(qslice, WildCards):
      self.wcs_stream += qslice
      self.pack()
    else:
      if isinstance(qslice, WildCards):
        wcs_len = self.len() + qslice.len()
      else:
        wcs_len = self.len() + len(qslice)
      wcs_count = wcs_len / 2
      self.wcs_stream = '[{}]'.format(str(wcs_count)) + '?' * (wcs_len % 2)
      self.packed = True

  def get(self):
    return self.wcs_stream

  def len(self):
    str_len = 0
    if self.packed:
      wcs_len = self.wcs_stream.lstrip('[').rstrip(']')
      question_index = self.wcs_stream.find('?')
      if question_index != -1:
        str_len = int(wcs_len.rstrip(']?')) * 2
        str_len += 1
      else: str_len = int(wcs_len) * 2
      return str_len
    else: return len(self.wcs_stream)

  def pack(self):
    if not self.packed:
      wcs_len = len(self.wcs_stream)
      if wcs_len > 3:
        wcs_count = (wcs_len / 2)
        self.wcs_stream = '[{}]'.format(str(wcs_count)) + '?' * (wcs_len % 2)
        self.packed = True

  def combine(self, next_object):
    if next_object:
      if isinstance(next_object, Bytes):
        if next_object.len() < 8:
          wcs_stream = '?' * next_object.len()
          self.append(wcs_stream)
        else: return -1
      else: self.append(next_object)
    return self


class VTGrepSearch(object):
  """Implements all the methods to launch queries to VTGrep.

    This class implements the whole process of receiving a range of memory
    addresses as input (or a string), creating a string buffer containing all
    the bytes in the range, and transforming some bytes (if desired) into
    wildcards to avoid memory addresses and offsets.

    The constructor has three parameters:
    - string: when searching a string selected in the strings window
    - addr_start and addr_end: begining and ending of the area selected
  """

  url = ''
  addr_start = 0
  addr_end = 0
  search_string = ''
  query_list = []
  _MIN_QUERY_SIZE = 7      # number of bytes
  _MAX_QUERY_SIZE = 2048   # Maximun length of a query string

  def __init__(self, *args, **kwargs):
    self.search_string = kwargs.get('string')
    self.addr_start = kwargs.get('addr_start')
    self.addr_end = kwargs.get('addr_end')

  @staticmethod
  def _get_instruction_bytes_wildcarded(pattern, addr, instr_type,
                                        op1_type, op2_type):
    """Replaces bytes related to offsets and memory locations with wildcards."""

    inst_prefix = idc.get_bytes(addr, 1).encode('hex')
    drefs = [x for x in idautils.DataRefsFrom(addr)]

    logging.debug(
        '[VTGREP] Wildcarding: %s',
        idc.generate_disasm_line(addr, 0)
        )

    # Known 2 bytes opcodes
    if inst_prefix in ('0f', 'f2', 'f3'):
      pattern = idc.get_bytes(addr, 2).encode('hex')
      inst_num_bytes = 2

    # CALLs or JUMPs using 2 bytes opcodes
    elif inst_prefix == 'ff' and (instr_type == idaapi.NN_jmp or
                                  instr_type == idaapi.NN_call):
      pattern = idc.get_bytes(addr, 2).encode('hex')
      inst_num_bytes = 2

    # A PUSH instruction using an inmediate value (mem offset)
    elif (inst_prefix == 'ff' and drefs and
          (op1_type == idaapi.o_imm or op2_type == idaapi.o_imm)):
      pattern = idc.get_bytes(addr, 2).encode('hex')
      inst_num_bytes = 2

    # No prefix is used
    else:
      pattern = inst_prefix
      inst_num_bytes = 1

    pattern += ' ' + '??' * (idc.get_item_size(addr) - inst_num_bytes) + ' '

    return pattern

  def _get_opcodes(self, addr, strict):
    """Replacing operands with wildcards when needed."""

    if strict:
      offsets_types = {idaapi.o_far, idaapi.o_mem, idaapi.o_imm}
    else:
      offsets_types = {idaapi.o_far, idaapi.o_mem}

    pattern = ''
    mnem = idautils.DecodeInstruction(addr)

    if mnem is not None:
      op1_type = mnem.Op1.type
      op2_type = mnem.Op2.type

      logging.debug(
          '[VTGREP] Instruction: %s',
          idc.generate_disasm_line(addr, 0)
          )

      inst_len = idc.get_item_size(addr)
      drefs = [x for x in idautils.DataRefsFrom(addr)]

      if (drefs and
          ((op1_type == idaapi.o_imm) or (op2_type == idaapi.o_imm)) or
          op1_type in offsets_types or op2_type in offsets_types):
          # Checks only if any operand constains a memory address
        pattern = self._get_instruction_bytes_wildcarded(
            pattern,
            addr,
            mnem.itype,
            op1_type,
            op2_type
            )
      else:
        if ((mnem.itype == idaapi.NN_call) or
            (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near)):
            # Checks if the instruction is a CALL (near or far) or
            # if it's a JMP (excluding near jumps)
          pattern = self._get_instruction_bytes_wildcarded(
              pattern,
              addr,
              mnem.itype,
              op1_type,
              op2_type
              )
        else:
          # In any other case, concatenate the raw bytes to the current string
          pattern = idc.get_bytes(addr, inst_len).encode('hex')
      return pattern
    else: return 0

  @staticmethod
  def _generate_slices(buf):
    """Read a string buffer and generates wildcards and bytes objects."""

    list_slices = buf.split()

    for qslice in list_slices:
      if qslice[0] == '?':
        yield WildCards(qslice)
      else:
        yield Bytes(qslice)

  def _create_query(self, buf):
    """Receives a string buffer and produces a query compatible with VTGrep."""

    query_slices = self._generate_slices(buf)
    query_list = []

    logging.debug('[VTGREP] Original query: %s', buf)

    for current in query_slices:
      if not query_list:
        query_list.append(current)
      else:
        prev = len(query_list) - 1
        qslice = query_list[prev].combine(current)

        if qslice == -1:
          query_list.append(current)
        else:
          query_list[prev] = qslice

    buf = ''.join(str(element.get()) for element in query_list)
    return self._sanitize(query_list)

  def _sanitize(self, qlist):
    """Applies some checks to the current query for VTGrep syntax compliance.

    Args:
      qlist: list of slices that must be checked according to VTGrep syntax

    Checks performed:
      - No ending []
      - No consecutive [][]
      - No consecutive byte strings
      - each slice must be 4 bytes long, at the very least
    """
    self.query_list = qlist
    modified = True

    while modified:
      modified = False
      query_len = len(qlist)
      qslice_index = 0

      for qslice_index in range(0, query_len):
        next_qslice_index = qslice_index + 1

        if (next_qslice_index) != query_len:
          next_qslice = self.query_list[next_qslice_index]
          qslice = self.query_list[qslice_index].combine(next_qslice)

          if qslice != -1:
            self.query_list[qslice_index] = qslice
            self.query_list.pop(next_qslice_index)
            modified = True
            break
        else:  # Last slice
          if self.query_list[qslice_index].combine(None) != -1:
            self.query_list.pop(qslice_index)
            modified = True
          break

    buf = ''.join(str(element.get()) for element in self.query_list)
    logging.debug('[VTGREP] Optimized query: %s', buf)
    return buf

  def search(self, wildcards=False, strict=False):
    """Processes current selection and generates a valid query for VTGrep.

    Args:
      wildcards:
        True:  search replacing offsets and memory locations with widlcards
        False: search for a sequence of bytes
      strict:
        True:  All the inmediate values (constants) are wildcarded
        False: Only values that are identified as offsets or memory addresses

    Checks current lines selected in the disassembly window, call the
    appropriate method for generating a valid query. Finally, open the
    (default) web browser to launch the query.
    """

    current = self.addr_start
    str_buf = ''
    len_query = 0

    if self.search_string:
      str_buf = self.search_string.encode('hex')
      len_query = len(str_buf)
    elif (self.addr_start == idaapi.BADADDR or
          self.addr_end == idaapi.BADADDR):
      logging.error('[VTGREP] Select a valid area.')
      exit
    elif (self.addr_end - self.addr_start) > self._MAX_QUERY_SIZE:
      logging.error('[VTGREP] The area selected is too large.')
      exit
    else:

      if wildcards:
        while current < self.addr_end:
          new_opcodes = self._get_opcodes(current, strict)
          if new_opcodes == 0: break
          else: str_buf += new_opcodes
          current = idc.next_head(current)
        if str_buf: str_buf = self._create_query(str_buf)
      else:
        str_buf = idc.get_bytes(
            self.addr_start,
            self.addr_end - self.addr_start
            )
        str_buf = str_buf.encode('hex')
      len_query = len(str_buf)

    if (len_query and self._MIN_QUERY_SIZE < len_query and
        len_query < self._MAX_QUERY_SIZE):

      str_buf = '{' + str_buf + '}'
      vtgrep_url = 'www.virustotal.com/gui/search/content:{}/files'
      self.url = 'https://{}'.format(urllib.quote(vtgrep_url.format(str_buf)))

      try:
        webbrowser.open_new(self.url)
      except:
        logging.error('[VTGREP] While opening web browser.')
      del self.query_list[:]
    else:
      logging.error('[VTGREP] Invalid query length or invalid area.')
