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
  """Class representing a slice of bytes in a search query."""

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

  def combinable(self, next_slice):
    # Check if current slice can be combined with the next slice
    if next_slice:
      if not isinstance(next_slice, Bytes) and self.len() >= 8:
        return False
    elif self.len() >= 8:
      return False
    return True

  def combine(self, next_slice):
    # Combine current slice with the next one
    if next_slice:
      if isinstance(next_slice, Bytes):
        self.append(next_slice)
        return self
      else:
        wcs_stream = '?' * self.len()
        next_slice.append(wcs_stream)
        return next_slice
    else:
      return self


class WildCards(object):
  """Class representing a slice of wildcards in a search query."""

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
      else:
        str_len = int(wcs_len) * 2
      return str_len
    else:
      return len(self.wcs_stream)

  def pack(self):
    if not self.packed:
      wcs_len = len(self.wcs_stream)
      if wcs_len > 3:
        wcs_count = (wcs_len / 2)
        self.wcs_stream = '[{}]'.format(str(wcs_count)) + '?' * (wcs_len % 2)
        self.packed = True

  def combinable(self, next_slice):
    # Check if the current slice can be combined with the next slice
    if next_slice:
      if isinstance(next_slice, Bytes) and next_slice.len() >= 8:
        return False
    return True

  def combine(self, next_slice):
    # Combine current slice with the next one
    if next_slice:
      if isinstance(next_slice, Bytes):
        wcs_stream = '?' * next_slice.len()
        self.append(wcs_stream)
      else:
        self.append(next_slice)
    return self


class VTGrepSearch(object):
  """Implements all the methods to launch queries to VTGrep.

    This class implements the whole process of receiving a range of memory
    addresses as input (or a string), creating a string buffer containing all
    the bytes in the range, and transforming some bytes (if desired) into
    wildcards to avoid memory addresses and offsets.

    The constructor has three parameters:
    - string: when searching a string selected in the strings window
    - addr_start and addr_end: begining and ending of an area cointainig code.
  """

  _MIN_QUERY_SIZE = 5      # number of bytes
  _MAX_QUERY_SIZE = 2048   # Maximun length of a query string

  def __init__(self, *args, **kwargs):
    self.string_searching = kwargs.get('string', False)
    self.addr_start = kwargs.get('addr_start', 0)
    self.addr_end = kwargs.get('addr_end', 0)

  @staticmethod
  def __get_instruction_bytes_wildcarded(pattern, addr, instr_type,
                                         op1_type, op2_type):
    """Replaces bytes related to memory addresses with wildcards.

    Args:
      pattern: current buffer containing the bytes of the current instruction.
      addr: the address of the current instruction to be wildcarded
      instr_type: type of the current instruction
      op1_type: type of the first operand
      op2_type: type of the second operand

    Returns:
      String: hex-encoded representation of the bytes obtained at addr where
              all the operands that refers to memmory addresses are wildcarded.
    """

    type_calls = frozenset([idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni])
    type_jumps = frozenset([idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni])

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
    elif inst_prefix == 'ff' and (instr_type in type_jumps or
                                  instr_type in type_calls):

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

  @staticmethod
  def __get_opcodes(addr, strict):
    """Get current bytes of the instruction pointed at addr.

    Args:
      addr: address of the current instruction
      strict: be more restrictive when applying wildcards (True) or not (False)

    Returns:
      String: hex-encoded representation of the bytes obtained at addr
    """

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
          '[VTGREP] Instruction: %s  [%d, %d, %d]',
          idc.generate_disasm_line(addr, 0),
          mnem.itype,
          op1_type,
          op2_type
          )

      inst_len = idc.get_item_size(addr)
      drefs = [x for x in idautils.DataRefsFrom(addr)]

      # Checks only if any operand constains a memory address
      if (drefs and
          ((op1_type == idaapi.o_imm) or (op2_type == idaapi.o_imm)) or
          op1_type in offsets_types or op2_type in offsets_types):
        pattern = VTGrepSearch.__get_instruction_bytes_wildcarded(
            pattern,
            addr,
            mnem.itype,
            op1_type,
            op2_type
            )
      # Checks if the instruction is a CALL (near or far) or
      # if it's a JMP (excluding near jumps)
      else:
        if ((mnem.itype == idaapi.NN_call) or
            (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near)):
          pattern = VTGrepSearch.__get_instruction_bytes_wildcarded(
              pattern,
              addr,
              mnem.itype,
              op1_type,
              op2_type
              )
        # In any other case, concatenate the raw bytes to the current string
        else:
          pattern = idc.get_bytes(addr, inst_len).encode('hex')
      return pattern
    else: return 0

  @staticmethod
  def __generate_slices(buf):
    """Read a string buffer and generates wildcards and bytes objects."""

    list_slices = buf.split()
    for qslice in list_slices:
      if qslice[0] == '?':
        yield WildCards(qslice)
      else:
        yield Bytes(qslice)

  @staticmethod
  def __sanitize(query_list):
    """Applies some checks to the current query for VTGrep syntax compliance.

    Args:
      query_list: list of slices that must be checked according to VTGrep syntax

    Checks performed:
      - No ending []
      - No consecutive [][]
      - No consecutive byte strings
      - each slice must be 4 bytes long, at the very least

    Returns:
      String: hex-encoded representation of the bytes obtained at addr
    """
    modified = True

    while modified:
      modified = False
      query_len = len(query_list)
      qslice_index = 0

      for qslice_index in range(0, query_len):
        next_qslice_index = qslice_index + 1

        if (next_qslice_index) != query_len:
          next_qslice = query_list[next_qslice_index]
          if query_list[qslice_index].combinable(next_qslice):
            qslice = query_list[qslice_index].combine(next_qslice)
            query_list[qslice_index] = qslice
            query_list.pop(next_qslice_index)
            modified = True
            break
        else:  # Last slice
          if query_list[qslice_index].combinable(None):
            query_list[qslice_index].combine(None)
            query_list.pop(qslice_index)
            modified = True
          break

    buf = ''.join(str(element.get()) for element in query_list)
    logging.debug('[VTGREP] Optimized query: %s', buf)
    return buf

  @staticmethod
  def __reduce_query(buf):
    """Receives a string buffer and returns a shorter version when possible.
    
    Receives a string buffer and produces a simplifyed version of the
    query string, where adjacents slices are combined when possible.
    
    Returns a list of slices where each slice can be a Bytes or 
    WildCards object.
    """

    query_slices = VTGrepSearch.__generate_slices(buf)
    reduced_list = []

    logging.debug('[VTGREP] Original query: %s', buf)

    for current in query_slices:
      if not reduced_list:
        reduced_list.append(current)
      else:
        prev = len(reduced_list) - 1
        if reduced_list[prev].combinable(current):
          reduced_list[prev] = reduced_list[prev].combine(current)
        else:
          reduced_list.append(current)

    buf = ''.join(str(element.get()) for element in reduced_list)
    return reduced_list

  def __create_query(self, wildcards, strict):
    """Returns a buffer containing all the bytes of the instructions selected.

      If there are instructions that contain offsets or memory addresses,
      their operands will be wildcarded.
    """

    current = self.addr_start
    str_buf = ''

    # Check if current selection is in a valid range
    if (self.addr_start == idaapi.BADADDR or
        self.addr_end == idaapi.BADADDR):
      logging.error('[VTGREP] Select a valid area.')
      return None
    elif (self.addr_end - self.addr_start) > self._MAX_QUERY_SIZE:
      logging.error('[VTGREP] The area selected is too large.')
      return None
    else:  # Selected area is valid

      if wildcards:  # Search for similar code
        while current < self.addr_end:
          new_opcodes = VTGrepSearch.__get_opcodes(current, strict)
          if new_opcodes == 0:
            break  # Unable to disassemble current address
          else:
            str_buf += new_opcodes
          current = idc.next_head(current)
      else:  # Search bytes
        str_buf = idc.get_bytes(
            self.addr_start,
            self.addr_end - self.addr_start
            )
        str_buf = str_buf.encode('hex')

    if str_buf:
      return str_buf
    else:
      return None

  def search(self, wildcards=False, strict=False):
    """Processes current selection and generates a valid query for VTGrep.

    Args:
      wildcards: search replacing offsets and memory locations with
        widlcards (True) or look for a sequence of bytes (False)
      strict: All the inmediate values (constants) are wildcarded (True)
        or wildcard only values that are identified as offsets or
        memory addresses (False)

    Checks current lines selected in the disassembly window, call the
    appropriate method to generate a valid query. Finally, open the
    (default) web browser to launch the query.
    """

    str_buf = ''

    if self.string_searching:
      str_buf = self.string_searching.encode('hex')
    else:
      str_buf = self.__create_query(wildcards, strict)
      if wildcards and str_buf is not None:
        str_buf = self.__sanitize(self.__reduce_query(str_buf))

    # After creating the search string, checks if new size is valid
    if str_buf is not None:
      len_query = len(str_buf)

      if (len_query and self._MIN_QUERY_SIZE < len_query and
          len_query < self._MAX_QUERY_SIZE):

        str_buf = '{' + str_buf + '}'
        vtgrep_url = 'www.virustotal.com/gui/search/content:{}/files'
        url = 'https://{}'.format(urllib.quote(vtgrep_url.format(str_buf)))

        try:
          webbrowser.open_new(url)
        except:
          logging.error('[VTGREP] Error while opening the web browser.')
    else:
      logging.error('[VTGREP] Invalid query length or invalid area.')
    