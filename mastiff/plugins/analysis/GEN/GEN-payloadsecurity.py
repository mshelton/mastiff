#!/usr/bin/env python
"""
  Copyright 2012-2013 The MASTIFF Project, All Rights Reserved.

  This software, having been partly or wholly developed and/or
  sponsored by KoreLogic, Inc., is hereby released under the terms
  and conditions set forth in the project's "README.LICENSE" file.
  For a list of all contributors and sponsors, please refer to the
  project's "README.CREDITS" file.
"""

__doc__ = """
Payload Security Online Submission plugin

Plugin Type: Generic
Purpose:
  This plug-in determines if the file being analyzed has been analyzed on
  https://www.hybrid-analysis.com previous.

  As of right now, there is no ability to submit malware since it requires
  a private API key.

  Information on the Payload Security API can be found at:
  https://www.hybrid-analysis.com/apikeys/info

Requirements:
  - A Payload Security API key is required to be entered into the configuration file.
    This can be obtained from www.hybrid-analysis.com.

Configuration Options:

  api_key: Your API key from hybrid-analysis.com. Leave this blank to disable the
  plug-in.

  secret:  Your API secret from hybrid-analysis.com.

Output:
   The results from Payload Security retrieval or submission will be placed into
   metascan-online.txt.

"""

__version__ = "$Id$"

import logging
import json
import urllib2
import os
import socket
import time

import mastiff.plugins.category.generic as gen

class GenPayloadSecurity(gen.GenericCat):
    """Payload Security plugin code."""

    def __init__(self):
        """Initialize the plugin."""
        self.api_key = None
        self.secret = None
        self.quota_wait = False
        gen.GenericCat.__init__(self)

    def _get(self, url):
        """Perform a basic GET request to the Payload Security API."""
        log = logging.getLogger('Mastiff.Plugins.' + self.name + '._get')

        headers = {'User-Agent' : 'VxStream'}

        # set up request
        log.debug('Submitting request to Payload Security')

        try:
            req = urllib2.Request(url, headers=headers)
            response = urllib2.urlopen(req, timeout=30)
        except urllib2.HTTPError, err:
            log.error('Unable to contact URL: %s', err)
            return None
        except urllib2.URLError, err:
            log.error('Unable to open connection: %s', err)
            return None
        except socket.timeout, err:
            log.error('Timeout when contacting URL: %s', err)
            return None
        except Exception, err:
            log.error('Unknown Error when opening connection: %s', err)
            return None

        data = response.read()
        try:
            response_dict = json.loads(data)
        except Exception:
            log.error('Error in Payload Security JSON response. Are you submitting too fast?')
            return None
        else:
            log.debug('Response received.')
            return response_dict

    def retrieve(self, sha256):
        """
        Retrieve results for this hash from Payload Security.
        """
        log = logging.getLogger('Mastiff.Plugins.' + self.name + '.retrieve')

        # Make the initial API connection
        url = "https://www.hybrid-analysis.com/api/scan/%s?apikey=%s&secret=%s" \
                % (sha256, self.api_key, self.secret)

        # Make the API call and wait if the quota has been reached.
        for i in xrange(20):
            data = self._get(url)
            if self.quota_wait is False:
                # We have been configured to NOT wait for an API to free up.
                return data
            elif data.has_key('response_code') and data['response_code'] == 0:
                # Query worked!
                return data
            elif data.has_key('response') and isinstance(data['response'], dict) \
                    and data['response'].has_key('error') \
                    and data['response']['error'].find('Exceeded maximum API requests') > -1:
                # Quota reached...  Wait and then try again.
                log.debug("Exceeded maximum Payload Security API requests.  Waiting.")
                time.sleep(60)
            else:
                # Something unexpected happened.  Exit out!
                log.error("Unexpected Payload Security API error:  %s", data)
                break

    def analyze(self, config, filename):
        """Analyze the file."""

        # sanity check to make sure we can run
        if self.is_activated is False:
            return False
        log = logging.getLogger('Mastiff.Plugins.' + self.name)
        log.info('Starting execution.')

        self.api_key = config.get_var(self.name, 'api_key')
        if self.api_key is None or len(self.api_key) == 0:
            log.error('No Payload Security API Key - exiting.')
            return False

        self.secret = config.get_var(self.name, 'secret')
        if self.secret is None or len(self.secret) == 0:
            log.error('No Payload Security API Secret - exiting.')
            return False

        quota_wait = config.get_var(self.name, 'quota_wait')
        if quota_wait.strip().lower() == "on":
            self.quota_wait = True
        else:
            self.quota_wait = False

        sha256 = config.get_var('Misc', 'hashes')[2]

        response = self.retrieve(sha256)
        if response is None:
            # error occurred
            log.error('Did not get a response from Payload Security. Exiting.')
            return False
        elif response.has_key('response') and isinstance(response['response'], dict) \
                and response['response'].has_key('error'):
            log.error(response['response']['error'])
            return False

        if sha256.upper() in response and response[sha256.upper()] == "Not Found":
            # The file has not been submitted
            log.info("File does not exist on Payload Security.")
        else:
            # write response to file
            self.output_file(config.get_var('Dir', 'log_dir'), response)

        return True

    def output_file(self, outdir, response):
        """Format the output from Payload Security results into a file. """
        log = logging.getLogger('Mastiff.Plugins.' + self.name + 'output_file')

        # Ensure that Payload Security returned a result.
        if response.has_key('response_code') and response['response_code'] == 0 \
                and len(response['response']) == 0:
            log.debug("Nothing found to write to report file.")
            return True

        try:
            mo_file = open(outdir + os.sep + 'payload-security.txt', 'w')
        except IOError, err:
            log.error('Unable to open %s for writing: %s',
                      outdir + 'payload-security.txt', err)
            return False

        mo_file.write(json.dumps(response['response'], indent=4) + "\n")
        mo_file.close()
        return True

