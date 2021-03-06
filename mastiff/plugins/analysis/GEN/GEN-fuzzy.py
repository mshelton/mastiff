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
Fuzzy Hashing plug-in

Plugin Type: Generic
Purpose:
  This plug-in generates the fuzzy hash of the given file.
  Also compares the fuzzy hashes against all of hashes already
  generated in the database.

Requirements:
  - ssdeep (http://ssdeep.sourceforge.net/)
  - pydeep (https://github.com/kbandla/pydeep)

Output:
   - fuzzy.txt - File listing the fuzzy hash of the file and any files that
     match.
   - The 'fuzzy' field will get added to the files table in the DB to store
     the fuzzy hash.

"""

__version__ = "$Id$"

import logging

try:
    import pydeep
except ImportError, error:
    print 'Gen-fuzzy: Could not import pydeep: %s'.format(error)

import mastiff.sqlite as DB
import sqlite3
import mastiff.plugins.category.generic as gen

class GenFuzzy(gen.GenericCat):
    """Fuzzy hashing plugin."""

    def __init__(self):
        """Initialize the plugin."""
        gen.GenericCat.__init__(self)
        self.page_data.meta['filename'] = 'fuzzy'
        # we will be adding to the file information hashes, so make sure it runs before us
        self.prereq = 'File Information'

    def analyze(self, config, filename):
        """Analyze the file."""

        # sanity check to make sure we can run
        if self.is_activated == False:
            return False
        log = logging.getLogger('Mastiff.Plugins.' + self.name)
        log.info('Starting execution.')
        log.info('Generating fuzzy hash.')

        try:
            my_fuzzy = pydeep.hash_file(filename)
        except pydeep.error, err:
            log.error('Could not generate fuzzy hash: %s', err)
            return False

        if self.output_db(config, my_fuzzy) is False:
            return False

        fuzz_results = list()
        if config.get_bvar(self.name, 'compare') is True:
            fuzz_results = self.compare_hashes(config, my_fuzzy)

        self.output_file(config, my_fuzzy, fuzz_results)

        return self.page_data

    def compare_hashes(self, config, my_fuzzy):
        """
           Compare the current hash to all of the fuzzy
           hashes already collected.
        """
        log = logging.getLogger('Mastiff.Plugins.' + self.name + '.compare')
        db = DB.open_db_conf(config)
        conn = db.cursor()

        log.info('Comparing fuzzy hashes.')

        fuzz_results = list()
        my_md5 = config.get_var('Misc', 'hashes')[0]
        query = 'SELECT md5, fuzzy FROM mastiff WHERE fuzzy NOT NULL'
        try:
            # compare current hash for all fuzzy hashes
            for results in conn.execute(query):
                percent = pydeep.compare(my_fuzzy, results[1])
                if percent > 0 and my_md5 != results[0]:
                    fuzz_results.append([results[0], percent])
        except sqlite3.OperationalError, err:
            log.error('Could not grab other fuzzy hashes: %s', err)
            return None
        except pydeep.error, err:
            log.error('pydeep error: %s', err)
            return None

        return fuzz_results

    def output_file(self, config, my_fuzzy, fuzz_results):
        """ Writes output to a file. """

        log = logging.getLogger('Mastiff.Plugins.' + self.name + '.output_file')

        if self.results['Generic']['File Information'] is None:
            # File Information is not present, cannot continue
            log.error('Missing File Information plug-in output. Aborting.')
            return False

        # add fuzzy hashes to the hashes already generated
        if self.results['Generic']['File Information'] is not None:
            # adding a new data onto an existing table
            my_table = self.results['Generic']['File Information']['File Hashes']
            my_table.addrow(['Fuzzy Hash', my_fuzzy])

        fuzz_table = self.page_data.addTable('Similar Fuzzy Hashes')

        if fuzz_results is not None and len(fuzz_results) > 0:
            fuzz_table.addheader([('MD5', str), ('Percent', str)])

            for (md5,  percent) in fuzz_results:
                fuzz_table.addrow([md5, percent])
        elif config.get_bvar(self.name, 'compare') is True:
            # This only gets printed if we actually compared
            fuzz_table.addheader([('Data', str)], printHeader=False)
            fuzz_table.addrow(['No other fuzzy hashes were related to this file.'])

        return True

    def output_db(self, config, my_fuzzy):
        """ Add fuzzy hash to the DB."""
        log = logging.getLogger('Mastiff.Plugins.' + self.name + '.DB_output')

        # open up the DB and extend the mastiff table to include fuzzy hashes
        db = DB.open_db_conf(config)

        # there is a possibility the mastiff table is not available yet
        # check for that and add it
        if DB.check_table(db,  'files')  == False:
            log.debug('Adding table "files"')
            fields = [ 'id INTEGER PRIMARY KEY',
                                   'sid INTEGER',
                                  'filename TEXT',
                                  'size INTEGER',
                                  'firstseen INTEGER',
                                  'lastseen INTEGER',
                                  'times INTEGER']
            if DB.add_table(db, 'files',  fields) is None:
                return False
            db.commit()

        if not DB.add_column(db, 'mastiff', 'fuzzy TEXT DEFAULT NULL'):
            log.error('Unable to add column.')
            return False

        conn = db.cursor()
        # update our hash
        sqlid = DB.get_id(db, config.get_var('Misc', 'Hashes'))
        query = 'UPDATE mastiff SET fuzzy=? WHERE id=?'
        try:
            conn.execute(query, (my_fuzzy, sqlid, ))
            db.commit()
        except sqlite3.OperationalError, err:
            log.error('Unable to add fuzzy hash: %s', err)
            return False

        db.close()
        return True

