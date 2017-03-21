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
FireEye AX Malware Analysis Submission Plug-in

Plugin Type: Generic
Purpose:
  This plug-in submits a file to a FireEye AX malware analysis 
  environment.  It requires a configured and properly working FireEye
  AX appliance with an API account.

  Information on the FireEye AX API can be found at:
  https://docs.fireeye.com/docs/index.html#AX

Requirements:
  - A properly configured FireEye AX environment 

  - A FireEye AX account with 'api_analyst' permissions

  - The Python requests library

Configuration Options:

  hostname:  The FireEye AX hostname

  user:  The FireEye AX user

  passwd:  The FireEye AX password

  mode:  Specifies the analysis mode. 0 = Sandbox, 1 = Live

  profile:  Specify the OS profile(s) to use

  timeout:  Sets the analysis timeout (in seconds)


Output:
   The results from FireEye AX analysis will be placed in fireeye_ax.txt.

"""

__version__ = "$Id$"

import json
import logging
import os
import re
import time

import requests
import mastiff.plugins.category.generic as gen

class AXConnection(object):
    """
    API connection to the FireEye AX appliance.
    """
    def __init__(self, host, user, passwd, verify=True):
        self.logger = logging.getLogger('Mastiff.Plugins.ModFireEyeAX.AXConnection')
        self.host = host
        self.verify = verify
        self.headers = {"Accept": "application/json"}

        # Authenticate
        auth_url = "https://%s/wsapis/v1.1.0/auth/login" % host
        self.logger.debug("Authenticating to FireEye AX:  %s", auth_url)
        auth = requests.post(auth_url,
                             auth=requests.auth.HTTPBasicAuth(user, passwd),
                             headers=self.headers,
                             verify=self.verify)

        if auth.status_code >= 200 and auth.status_code < 300:
            self.logger.debug("Successfully authenticated!")
        else:
            self.logger.error("Unable to authenticate to the API!")
            raise Exception("Unable to authenticate to the API!")

        self.headers['X-FeApi-Token'] = auth.headers['X-FeApi-Token']

    def get(self, endpoint):
        """Issue a GET request to the AX API."""
        url = "https://%s/wsapis/v1.1.0%s" % (self.host, endpoint)
        self.logger.debug("Issuing API Call:  %s", url)
        request = requests.get(url,
                               headers=self.headers,
                               verify=self.verify)
        return json.loads(request.text)

    def post(self, endpoint, data):
        """Issue a POST request to the AX API."""
        url = "https://%s/wsapis/v1.1.0%s" % (self.host, endpoint)
        self.logger.debug("Issuing API Call:  %s / Data: %s", url, data)
        request = requests.post(url,
                                headers=self.headers,
                                data=data,
                                verify=self.verify)
        return json.loads(request.text)


    def submit(self, filename, profiles=["win7x64-sp1", "win7-sp1"], \
                analysis_type=0, timeout=500, application=-1, \
                force=False, prefetch=1, priority=0):
        """
        Submit a malware sample to the FireEye AX appliance.

        filename (string) - A file to submit to the FireEye AX
        application (list of strings) - Specified the ID of the application to be
                             used for analysis.
        timeout (int) - Sets the analysis timeout (in seconds)
        priority (0 or 1) - Sets the analysis priortity.
                             0 = Normal, 1 = Urgent
        profiles (int) - The AX OS profile to use for analysis.
        analysis_time (1 or 0) - Specifies the analysis mode.
                             0 = Sandbox, 1 = Live
        force (bool) - Specifies whetehr to perform an analysis on the
                       file even if the file exaclty matches an
                       analysis that has already been performed.
        prefetch (int) - Specifies whether to determine the file
                          target based on an internal determination
                          rather than browsing to the target location.
                          0 = False, 1 = True

        @return -1 for failure, request ID for success
        """
        url = "https://%s/wsapis/v1.1.0/submissions" % self.host

        # Create the data structures expected by FireEye AX.
        files = {'filename' : open(filename, 'rb')}
        data = {"analysistype" : analysis_type, "priority" : priority, \
                 "profiles" : profiles, "force" : force, \
                 "application" : application, "prefetch" : prefetch, \
                 "timeout" : timeout}
        self.logger.debug("Submitting the following options:  %s", json.dumps(data))

        # Submit request
        self.logger.info("Submitting sample to FireEye AX:  %s", filename)
        request = requests.post(url, headers=self.headers, verify=self.verify,
                                data={'options' : json.dumps(data)}, \
                                files=files \
        )

        # Determine whether the request was successful
        if request.status_code >= 200 and request.status_code < 300:
            data = json.loads(request.text)
            return data[0]['ID']
        else:
            self.logger.error("%s:  %s", request.status_code, request.text)
            return -1

    def logout(self):
        """Log out from the FireEye AX appliance."""
        self.logger.debug("Logging out of the FireEye AX")
        request = requests.post("https://%s/wsapis/v1.1.0/auth/logout" % self.host,
                                headers=self.headers,
                                verify=self.verify)
        if request.status_code < 200 or request.status_code >= 300:
            self.logger.error("Unable to log out - %s", request.text)
            raise Exception("Unable to log out - %s" % request.text)

class GenFireEyeAX(gen.GenericCat):
    """FireEye AX plugin code."""

    def __init__(self):
        """Initialize the plugin."""
        gen.GenericCat.__init__(self)
        self.ax_conn = None
        self.profile = []
        self.hostname = None
        self.user = None
        self.passwd = None
        self.verify = True
        self.mode = 0
        self.timeout = 60

    def retrieve(self, md5):
        """
        Retrieve results for this hash from the FireEye AX appliance.
        """

        log = logging.getLogger('Mastiff.Plugins.' + self.name + '.retrieve')

        # set up request
        log.debug('Looking up the file hash in the FireEye AX')

        try:
            data = self.ax_conn.get("/alerts?md5=%s&info_level=extended" % md5)

        except Exception, ex:
            log.exception('Unknown Error when opening connection:  %s', ex)
            return None

        # Determine whether there is an existing submission in the AX
        if isinstance(data, dict) is False:
            log.error("The JSON returned is not properly formated:  %s", data)
        elif data.has_key("alertsCount") and data['alertsCount'] == 0:
            log.debug("No existing submissions found in the FireEye AX")
            return None
        elif data.has_key("alertsCount") and data['alertsCount'] > 0:
            log.debug("%d existing submission(s) found in the FireEye AX", \
                      data['alertsCount'])
            return data['alert']
        else:
            log.error("Unknown data structure returned:  %s", data)
            return None

    def submit(self, config, filename):
        """
        Submit the sample to the FireEye AX for analysis
        """
        log = logging.getLogger('Mastiff.Plugins.' + self.name + '.submit')

                # Submit sample to the FireEye AX
        try:
            submission_id = self.ax_conn.submit(filename, self.profile, self.mode, self.timeout)

        except Exception, ex:
            log.exception('Received unknown error during sample submission:  %s', ex)
            return None

        # Ensure that the submission was successful
        if submission_id == -1:
            return None

        # Determine whether to wait for the submission to complete
        if config.get_bvar(self.name, 'wait') is False:
            # Don't wait, just return the submission ID
            return {"submission_id" : submission_id}

        # Loop until the submission has finished
        while True:
            status = self.ax_conn.get('/submissions/status/%s' % submission_id)
            log.debug("[ID: %s] Status:  %s", submission_id, status)
            if status['submissionStatus'] == "Done":
                # Download the report and return it
                report = self.ax_conn.get( \
                        "/submissions/results/%s?info_level=extended" \
                        % submission_id)
                if report.has_key("alert"):
                    return report['alert']
                else:
                    log.error("The report did not return what was expected:  %s", report)

            else:
                # Check the report in a few seconds
                time.sleep(16)

        return None

    def analyze(self, config, filename):
        """Analyze the file."""

        # sanity check to make sure we can run
        if self.is_activated is False:
            return False
        log = logging.getLogger('Mastiff.Plugins.' + self.name)
        log.info('Starting execution.')

        # Retrieve the FireEye AX hostname
        self.hostname = config.get_var(self.name, 'hostname')
        if self.hostname is None or len(self.hostname) == 0:
            return False

        # Retrieve the FireEye AX username
        self.user = config.get_var(self.name, 'user')
        if self.user is None or len(self.user) == 0:
            log.error("No FireEye AX username specified - exiting.")
            return False

        # Retrieve the FireEye AX password
        self.passwd = config.get_var(self.name, 'passwd')
        if self.passwd is None or len(self.passwd) == 0:
            log.error("No FireEye AX password specified - exiting.")
            return False

        # Determine whether to verify that the SSL certificate is valid.
        verify = config.get_var(self.name, 'verify')
        if verify is False or verify.lower().find("false") > -1:
            log.warn("The FireEye AX will not verify the TLS certificate!")
            self.verify = False
        else:
            self.verify = True

        # Determine the analysis mode (0 = sandbox, 1 = live)
        mode = config.get_var(self.name, 'mode')
        if mode == "1":
            self.mode = 1
        else:
            self.mode = 0

        # Determine the OS profile(s) to use
        profile = config.get_var(self.name, 'profile')
        if profile is False or len(profile) == 0:
            self.profile = ["win7x64-sp1", "win7-sp1"]
        else:
            self.profile = profile.split(",")

        # Determine the analysis timeout (in seconds)
        timeout = config.get_var(self.name, 'timeout')
        if timeout is False or len(timeout) == 0:
            self.timeout = 60
        else:
            try:
                self.timeout = int(timeout)
            except ValueError:
                log.warn("Unable to convert 'timeout' value to a number:  %s", timeout)
                self.timeout = 60

        # Debug -- Log the configuration parameters.
        log.debug("FireEye AX Configuraiton:  (hostname: %s) (user: %s) " \
                  + "(passwd: ****) (verify: %s) (mode: %s) (profile: %s) " \
                  + "(timeout: %s)", self.hostname, self.user, self.verify, \
                  self.mode, self.profile, self.timeout)

        # Create a connection to the FireEye AX appliance and store it
        # for use by all the class methods.
        self.ax_conn = AXConnection(self.hostname, self.user, self.passwd, self.verify)

        # Lookup the file in the FireEye AX to see if it already exists.
        md5 = config.get_var('Misc', 'hashes')[0]
        data = self.retrieve(md5)

        if data is None:
            # Submit file to the FireEye AX for analysis
            data = self.submit(config, filename)

        if data is not None:
            # write response to file
            self.output_file(config.get_var('Dir', 'log_dir'), data)

        return True

    def output_file(self, outdir, response):
        """Write the FireEye AX report data to disk."""
        log = logging.getLogger('Mastiff.Plugins.' + self.name + 'output_file')

        try:
            report_full = open(outdir + os.sep + 'fireeye_ax-full.txt', 'w')
            report_quick = open(outdir + os.sep + 'fireeye_ax-quick.txt', 'w')
        except IOError, err:
            log.error('Unable to open the output file for writing:  %s', err)
            return False

        # Write the entire report to disk
        report_full.write(json.dumps(response, indent=4) + "\n")
        report_full.close()

        # Write a subset of the report to disk.  This is going to take
        # more JSON parsing!
        alerts = []
        for res in response:
            malware = {}
            # Parse out the malware signature names
            if res.has_key('explanation') \
                    and res['explanation'].has_key('malwareDetected') \
                    and res['explanation']['malwareDetected'].has_key('malware'):
                for mal in res['explanation']['malwareDetected']['malware']:
                    if mal.has_key('name'):
                        malware[mal['name']] = True

            # Parse out CNC services
            domains = {}
            ips = {}
            r_ip = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            if res.has_key('explanation') \
                    and res['explanation'].has_key('cncServices') \
                    and res['explanation']['cncServices'].has_key('cncService'):
                for cnc in res['explanation']['cncServices']['cncService']:
                    address = cnc['address']
                    if r_ip.match(address):
                        ips[address] = True
                    else:
                        domains[address] = True

            # Create the actual alert record
            alert = {
                'occurred' : res.get('occurred', None),
                'name'     : res.get('name', None),
                'alertUrl' : res.get('alertUrl', None),
                'severity' : res.get('severity', None),
                'malware'  : malware.keys(),
                'hosts'    : ips.keys(),
                'domains'  : domains.keys(),
            }
            alerts.append(alert)

        # Write the simple report to disk.
        report_quick.write(json.dumps(alerts, indent=4) + "\n")
        report_quick.close()

        return True

