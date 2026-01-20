# Copyright 2025 Google LLC. All Rights Reserved.
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
import json
import base64


class CI_Notebook(object):
  """Manages a collection of Code Insight analysis results.

  This class acts as an in-memory database for storing, retrieving, and
  managing analysis "pages" for different functions within a binary. Each page
  is keyed by the function's memory address.
  """

  def __init__(self):
    """Initializes a new, empty Code Insight notebook."""
    self.notebook = {}

  def import_data(self, ci_dict):
    """Imports data from a dictionary, merging it into the current notebook.

    Args:
      ci_dict (dict): Dictionary containing data to import. Existing keys
                      in the current notebook will be overwritten if they
                      match keys in the imported dictionary.
    """
    try:
      self.notebook.update(ci_dict)
    except (TypeError, ValueError):
      logging.error('[VT Plugin] ERROR importing the file.')

  def get_total(self):
    """Gets the total number of pages (functions) in the notebook.

    Returns:
      int: The total number of pages, or 0 if the notebook is empty.
    """
    return len(self.notebook)

  def get_functions(self):
    """Gets all function addresses (keys) present in the notebook.

    Returns:
      A view of the notebook's keys (function addresses as hex strings).
    """
    return self.notebook.keys()

  def get_page(self, func_addr):
    """
    Retrieves the data for a specific page from the notebook.

    Args:
      func_addr (str): The function address (key as a hex string)
                       for the page to retrieve.

    Returns:
      dict: A dictionary containing the page data if found,
            or None if the address does not exist in the notebook.
    """
    return self.notebook.get(func_addr)

  @staticmethod
  def encode_response(summary, description):
    """
    Encodes a summary and description into a Base64-encoded JSON string.

    Args:
      summary (str): The summary to encode.
      description (str): The description to encode.

    Returns:
      str: The Base64 encoded JSON string (ASCII format).
    """
    response = {
      "summary": summary,
      "description": description
    }
    try:
      response_str = json.dumps(response)
    except TypeError:
      logging.error('[VT Plugin] ERROR encoding CI response (not serializable).')
      response_str = "{}"
    encoded_response = base64.b64encode(response_str.encode('utf-8'))
    return encoded_response.decode('ascii')

  def add_page(self, func_name, func_addr, code_type, b64code, summary, description, expected_summary, expected_description):
    """Adds a new page to the notebook or updates an existing one.

    Args:
      func_name (str): Name of the function.
      func_addr (str): Function address (key as a hex string).
      code_type (str): Type of code (e.g., 'disassembled', 'decompiled').
      b64code (str): Base64 encoded source code of the function.
      summary (str): Original summary provided by CodeInsight.
      description (str): Original description provided by CodeInsight.
      expected_summary (str): User-expected or modified summary.
      expected_description (str): User-expected or modified description.
    """
    logging.debug("[VT Plugin] Adding or updating page for %s", func_addr)
    page = {
        'func_name': func_name,
        'code_type': code_type,
        'b64code': b64code,
        'summary': summary,
        'description': description,
        'expected_summary': expected_summary or None,
        'expected_description': expected_description or None,
    }
    self.notebook[func_addr] = page
    logging.debug("[VT Plugin] CI Notebook content: %s", self.show_pages())


  def discard_page(self, func_addr):
    """
    Removes a page from the notebook.

    Args:
      func_addr (str): The function address (key as a hex string)
                       of the page to be removed.
    """
    if self.notebook.pop(func_addr, None):
      logging.debug('[VT Plugin] Page for %s discarded.', func_addr)
      self.show_pages()
    else:
      logging.debug('[VT Plugin] Attempted to discard non-existent page for %s', func_addr)

  def show_pages(self):
    """
    Logs the current function keys (debug level) and returns the entire notebook.

    Returns:
      dict: The complete notebook dictionary.
    """
    logging.debug("[VT Plugin] Current functions: %s", str(self.notebook.keys()))
    return self.notebook
