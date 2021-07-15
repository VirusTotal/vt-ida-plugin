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
import ida_idp
import ida_search
import ida_segment
import idaapi
import idautils
import idc
import logging


class NavigateDisassembler(object):

  @staticmethod
  def go_to_ea(str_addr):
    ea = int(str_addr, 0)
    if ea is not None and ea is not idc.BADADDR:
      idaapi.jumpto(ea)
    else:
      logging.debug('[VT Disassembler] Not valid EA: %s', str_addr)

  @staticmethod
  def is_head(ea):
    flags = idc.get_full_flags(ea)
    return idc.is_head(flags)

  @staticmethod
  def is_imports(segment):
    if segment in ('.idata', '.rdata', '.edata'):
      # Check: .dynstr, '.dynsym', __IMPORT
      return True
    return False


class SearchEvidence(object):

  @staticmethod
  def __filter_address(addr, segment, source, action):
    if ((source == 'file names' and NavigateDisassembler.is_head(addr)) or
      (action in ('Calls highlighted', 'Modules loaded', 'Files opened') and
      NavigateDisassembler.is_imports(segment))):
      return True
    return False

  def search_text(self, content, source, action, max_results):
    """A text string is reveived as a parameter"""

    addr = idc.get_inf_attr(idaapi.INF_MIN_EA)
    list_results = []
    logging.debug('[VT Disassembler] Searching text: %s', content)

    for i in range(0, max_results):
      addr = ida_search.find_text(addr, 0, 0, content, ida_search.SEARCH_DOWN)
      result = {}
      if addr == idc.BADADDR:
        break

      result['addr'] = addr
      result['function_name'] = idaapi.get_func_name(addr)
      if result['function_name']:
        function = idaapi.get_func(addr)
        result['function_addr'] = function.start_ea
      else:
        result['function_addr'] = None
      segment = ida_segment.getseg(addr)
      result['segment'] = ida_segment.get_segm_name(segment)

      if result and not self.__filter_address(addr,
                                              result['segment'],
                                              source,
                                              action):
        list_results.append(result)
      addr = idc.next_head(addr)

    if list_results:
      logging.info('[VT Disassembler] Evidence FOUND!: %s', list_results)
    return list_results

  def search_bytes(self, content, source, action, max_results):
    logging.debug('[VT Disassembler] Searching bytes: %s', content)

    addr = idc.get_inf_attr(idaapi.INF_MIN_EA)
    list_results = []

    for i in range(0, max_results):
      addr = ida_search.find_binary(addr,
                                    idaapi.BADADDR,
                                    content,
                                    16,
                                    ida_search.SEARCH_DOWN)
      result = {}
      if addr == idc.BADADDR:
        break

      result['addr'] = addr
      result['function_name'] = idaapi.get_func_name(addr)
      if result['function_name']:
        function = idaapi.get_func(addr)
        result['function_addr'] = function.start_ea
      else:
        result['function_addr'] = None
      segment = ida_segment.getseg(addr)
      result['segment'] = ida_segment.get_segm_name(segment)

      if result and not self.__filter_address(addr,
                                              result['segment'],
                                              source,
                                              action):
        list_results.append(result)
      addr = idc.next_head(addr)

    if list_results:
      logging.info('[VT Disassembler] Evidence FOUND!: %s', list_results)
    return list_results


class Disassembler(object):

  @staticmethod
  def bad_address():
    return idaapi.BADADDR

  @staticmethod
  def next_address(addr):
    return idc.next_head(addr)

  @staticmethod
  def get_bytes(start_addr, end_addr):
    return idc.get_bytes(
        start_addr,
        end_addr - start_addr
        )

  @staticmethod
  def valid_address_range(start_addr, end_addr):
    if (start_addr == Disassembler.bad_address() or
        end_addr == Disassembler.bad_address()):
      return False
    else:
      return True

  @staticmethod
  def valid_range_size(start_addr, end_addr, max_size):
    if (end_addr - start_addr) > max_size:
      return False
    else:
      return True

  @staticmethod
  def wildcard_instruction(addr):
    """Replaces bytes related to memory addresses with wildcards.

    Args:
      addr: the address of the current instruction to be wildcarded

    Returns:
      String: hex-encoded representation of the bytes obtained at addr where
              all the operands that refers to memmory addresses are wildcarded.
    """

    pattern = ''
    mask = ida_idp.ph_calcrel(addr)
    # IDA > 7.5 return a list, < 7.5 returns a byte object
    if idaapi.IDA_SDK_VERSION >= 750:
      mask_bytes = mask[0]
      mask_str = binascii.hexlify(mask_bytes).decode('utf-8')
    else:
      mask_str = binascii.hexlify(mask).decode('utf-8')

    logging.debug(
        '[VT Disassembler] Wildcarding: %s',
        idc.generate_disasm_line(addr, 0)
        )

    current_byte = 0
    index_instr = 0
    pattern = ' '

    while current_byte < len(mask_str):
      if mask_str[current_byte] != '0' or mask_str[current_byte+1] != '0':
        pattern += '?? '
      else:
        instr_bytes = idc.get_bytes(addr+index_instr, 1)
        pattern += binascii.hexlify(instr_bytes).decode('utf-8') + ' '
      current_byte += 2
      index_instr += 1

    logging.debug('[VT Disassembler] Wildcarded: %s', pattern)

    return pattern

  @staticmethod
  def get_opcodes(addr, strict):
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
          '[VT Disassembler] Instruction: %s  [%d, %d, %d]',
          idc.generate_disasm_line(addr, 0),
          mnem.itype,
          op1_type,
          op2_type
          )

      inst_len = idc.get_item_size(addr)
      drefs = [x for x in idautils.DataRefsFrom(addr)]

      # Checks if any operand constains a memory address
      if (drefs and
          ((op1_type == idaapi.o_imm) or (op2_type == idaapi.o_imm)) or
          op1_type in offsets_types or op2_type in offsets_types):
        pattern = Disassembler.wildcard_instruction(addr)
      # Checks if the instruction is a CALL (near or far) or
      # if it's a JMP (excluding near jumps)
      else:
        if ((mnem.itype == idaapi.NN_call) or
            (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near)):
          pattern = Disassembler.wildcard_instruction(addr)
        # In any other case, concatenate the raw bytes to the current string
        else:
          pattern = binascii.hexlify(idc.get_bytes(addr, inst_len))
          pattern = pattern.decode('utf-8')
      return pattern
    else: return 0

 