# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2015/12/31

Description:
RegistryMatching.py is a Vestigium module to perform Windows Registry analysis.

Copyright (c) 2015, Thomas Laurenson

###############################################################################
This file is part of Vestigium.

Vestigium is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
###############################################################################
"""

__version__ = "1.0.0"

import os
import sys
import logging
import collections
import glob
import hashlib
import io
import xml.dom.minidom

try:
    import dfxml
except ImportError:
    print('Error: RegistryProcessing.py')
    print('       The dfxml.py module is required.')
    print('       You can download from: https://github.com/simsong/dfxml')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import Objects
except ImportError:
    print('Error: RegistryProcessing.py')
    print('       The Objects.py module is required.')
    print('       You can download from: https://github.com/simsong/dfxml')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import apxml
except ImportError:
    print('Error: RegistryProcessing.py')
    print('       The apxml.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/apxml')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import FilePathNormalizer
except ImportError:
    print('Error: RegistryProcessing.py')
    print('       The FilePathNormalizer.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/Vestigium')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import CellPathNormalizer
except ImportError:
    print('Error: RegistryProcessing.py')
    print('       The CellPathNormalizer.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/Vestigium')
    print('       Now Exiting...')
    sys.exit(1)

################################################################################
# Helper methods
def sha1_file(fi):
    """ Helper method to calculate SHA-1 hash value of a file. """
    hasher = hashlib.sha1()
    with open(fi, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def ptime(self, t):
    """ Return the requested time format. 't' is a dfxml time value. """
    if t is None:
        return "null"
    if self.timestamp:
        return str(t.timestamp())
    else:
        return str(t.iso8601())

def match_cell_path(tco, pco):
    """ Match the full path of target cellobject (tco) against the
        profile cellobject. """
    return tco.cellpath_norm == pco.cellpath_norm

def match_cell_type(tco, pco):
    """ Match the cell type (key or value) of the target cellobject (tco)
        against the profile cellobject (pco). """
    return tco.name_type == pco.name_type

def match_cell_alloc(tco, pco):
    """ Match the cell allocation of the target
        cellobject (tco) against the profile cellobject (pco). """
    return  tco.alloc == pco.alloc

def match_data_type(tco, pco):
    """ Match the cell data type (string, int etc.) of the target
        cellobject (tco) against the profile cellobject. """
    return  tco.data_type == pco.data_type

def match_data(tco, pco):
    """ Match the actual cell data contents of the target cellobject (tco)
        against the profile cellobject (pco). """
    return tco.data == pco.data_raw

################################################################################
class RegistryProcessing():
    def __init__(self, imagefile=None, xmlfile=None, outputdir=None, profiles=None, hives_dir=None, timestamp=False):
        """ Initialize RegistryMatching object. """
        self.imagefile = imagefile
        self.xmlfile = xmlfile
        self.outputdir = outputdir
        self.hives_dir = hives_dir
        self.profiles = profiles
        self.timestamp = timestamp

        # Print banner for Registry processing
        #print("\n\n----------------------------------------")
        #print(">>> PERFORMING WINDOWS REGISTRY ANALYSIS")
        #print("----------------------------------------")
        logging.info("\n----------------------------------------")
        logging.info(">>> PERFORMING WINDOWS REGISTRY ANALYSIS")
        logging.info("----------------------------------------")

        # List of Profile CellObjects
        self.pcos = list()

        # A dictionary is generated: state => list of fileobjects.
        # For example: "install" => [cellobject, cellobject] """
        self.pcos_dict = collections.defaultdict(list)

        self.pcos_keys = collections.defaultdict(list)
        self.pcos_values = collections.defaultdict(list)

        # Set of target hive files to process
        self.target_hives = set()

        # Store the Target Data Set (all HIVES) in a RegXML object
        self.tds_regxml = Objects.RegXMLObject()

        # Store the Profile CellObjects in a RegXML object
        self.pco_regxml = Objects.RegXMLObject()

        # Initialize the file path normalizer object
        self.file_path_normalizer = FilePathNormalizer.FilePathNormalizer()

        # Initialize the cell path normalizer object
        self.cell_path_normalizer = CellPathNormalizer.CellPathNormalizer()

        # Create a list for cell matches
        self.matches = list()

        # Counter for target CellObjects to display progress
        self.target_key_count = 0
        self.target_value_count = 0
        self.matches_count = 0

        # active_hive specifies the hive name (base name) for the hive being processed
        self.active_hive = None

        # active_rootkey is the common root key name (SOFTWARE, SYSTEM, NTUSER.DAT)
        self.active_rootkey = None

    def process_apxmls(self):
        """
        Method to parse the RegXML CellObjects from the
        Application Profile XML structure.
        """
        #print(">>> Processing application profiles ...")
        logging.info("\n>>> Application profile information:")

        # Process each target Application Profile XML (APXML) document
        for profile in self.profiles:
            #print("  > Processing: %s" % os.path.basename(profile))
            apxml_obj = apxml.iterparse(profile)
            apxml.generate_stats(apxml_obj)
            for pco in apxml_obj:
                if isinstance(pco, Objects.CellObject):
                    # Normalise the CellObject properties
                    # This is commented out, as apxml/APXMLPreProcess.py now performs normalisation
                    # See: https://github.com/thomaslaurenson/apxml/blob/master/APXMLPreProcess.py

                    """
                    obj.cellpath_norm = cell_path_normalizer.normalize_profile_co(obj.cellpath)
                    rootkey = obj.cellpath_norm.split("\\")[0]
                    obj.cellpath_norm = cell_path_normalizer.normalize_target_co(obj.cellpath_norm, rootkey)

                    # Normalize the basename
                    obj.basename_norm = None
                    if obj.basename and obj.basename.startswith("C:"):
                        normbasename = file_path_normalizer.normalize(obj.basename)
                        normbasename = normbasename.replace('/', '\\')
                        obj.basename_norm = normbasename
                        obj.cellpath_norm = obj.cellpath_norm.replace(obj.basename, obj.basename_norm)

                    # Set the application name
                    obj.app_name = apxml_obj.metadata.app_name
                    """

                    # Add Profile CellObject (PCO) to:
                    # 1) PCO list
                    # 2) PCO dictionary
                    self.pcos.append(pco)
                    self.pcos_dict[pco.cellpath_norm].append(pco)

                    if pco.name_type == "k":
                        self.pcos_keys[pco.cellpath_norm].append(pco)
                    elif pco.name_type == "v":
                        self.pcos_values[pco.cellpath_norm].append(pco)

                    # Get set of required hives based on profile entries
                    rootkey = pco.cellpath_norm.split("\\")[0]
                    self.target_hives.add(rootkey)
                    pco.rootkey = rootkey

                    # Also append PCO to a RegXML object
                    self.pco_regxml.append(pco)

                    # Log all profile entries (Application, State, Path)
                    logging.info("    %s\t%s\t%s" % (apxml_obj.metadata.app_name,
                                                     pco.app_state,
                                                     pco.cellpath_norm))

        # Log all target hive names (rootkey)
        logging.info("\n>>> Target Registry hives:")
        for rootkey in self.target_hives:
            logging.info("  > %s" % rootkey)

    def parse_target(self):
        """ Parse target Registry hive files. """

        # Print header to console
        #print("\n>>> Processing target hives ...")

        self.to_process = collections.defaultdict(list)

        # Fetch all Registry related files
        registry_files = glob.glob(self.hives_dir + "*")

        # Classify required target hives and hive files
        for fi in registry_files:
            for rootkey in self.target_hives:
                if fi.lower().endswith(rootkey.lower() + ".xml"):
                    self.to_process[rootkey].append(fi)

        logging.info("\n>>> Target Registry hive files:")
        for k in self.to_process:
            for v in self.to_process[k]:
                logging.info("  > %s\t%s" % (k,v))

        # Start processing each Registry hive
        logging.info("\n>>> DETECTED REGISTRY ARTIFACTS:")
        for rootkey in self.target_hives:
            # Can exclude rootkeys during testing to speed up processing
            #if rootkey == "NTUSER.DAT" or rootkey == "SOFTWARE":
            #    continue

            for hive in self.to_process[rootkey]:
                #print("  > %s" % os.path.basename(hive))
                self.active_hive = hive
                self.active_rootkey = rootkey

                for (event, obj) in Objects.iterparse_CellObjects(hive):
                    if isinstance(obj, Objects.CellObject):
                        obj.rootkey = rootkey
                        self.process_target_co(obj)

    def process_target_co(self, tco):
        """ Process each Target CellObject (TCO). """

        # Registry count progress indicator
        if tco.name_type == 'k':
            self.target_key_count += 1
        elif tco.name_type == 'v':
            self.target_value_count += 1
        #sys.stdout.write("\r  > Keys: {0:6}  Values: {1:6}  Matches: {2:4}  Hive: {3:10}".format(self.target_key_count, self.target_value_count, self.matches_count, self.active_rootkey));

        # Normalize the TCO rootkey
        if tco.cellpath is not None:
            tco.cellpath_norm = self.cell_path_normalizer.normalize_target_co_rootkey(tco.cellpath.lower(),
                                                                                  self.active_rootkey)

            # Normlaize the TCO cell path (full path)
            tco.cellpath_norm = self.cell_path_normalizer.normalize_target_co(tco.cellpath_norm,
                                                                          self.active_rootkey)
        else:
            tco.cellpath_norm == None
                        
        # Normalize the basename
        tco.basename_norm = None
        if tco.basename and tco.basename.startswith("c:"):
            normbasename = self.file_path_normalizer.normalize(tco.basename)
            normbasename = normbasename.replace('/', '\\')
            tco.basename_norm = normbasename
            if tco.cellpath_norm:
                tco.cellpath_norm = tco.cellpath_norm.replace(tco.basename,
                                                              tco.basename_norm)
        #print(tco.cellpath_norm)
        if tco.name_type == 'k':
            if tco.cellpath_norm in self.pcos_keys:
                for pco in self.pcos_keys[tco.cellpath_norm]:
                    self.match_tco_pco(tco, pco)

        if tco.name_type == 'v':
            if tco.cellpath_norm in self.pcos_values:
                for pco in self.pcos_values[tco.cellpath_norm]:
                    self.match_tco_pco(tco, pco)

    def match_tco_pco(self, tco, pco):
        """ Match the Target CellObject (TCO) to Profile CellObjects (PCO). """
        #if "truecrypt" in tco.cellpath_norm.lower():
        #    print(tco.cellpath_norm)
        #    print(pco.cellpath_norm)
        # Match Registry key (path, allocation)
        if tco.name_type == "k":
            if (match_cell_path(tco, pco) and
                match_cell_alloc(tco, pco)):
                ##print("FOUND KEY: %s" % tco.cellpath_norm)

                # Add in matched annotation, append matched PCO, specify hive
                tco.annos = {"matched"}
                tco.original_cellobject = pco
                tco.active_hive = self.active_hive
                # Log matched entries, append matched TCO to matches
                logging.info("  > KEY: %s\t%s" % (tco.cellpath,
                                                  tco.alloc))
                logging.info("         %s\t%s\t%s\t%s" % (pco.app_name,
                                                          pco.app_state,
                                                          pco.cellpath_norm,
                                                          pco.alloc))
                self.matches.append(tco)
                self.matches_count += 1
                return

        # Match Registry value
        elif tco.name_type == "v":
            # Hard match: path, data type, actual data, allocation
            if (match_cell_path(tco, pco) and
                match_data_type(tco, pco) and
                match_data(tco, pco) and
                match_cell_alloc(tco, pco)):
                ##print("FOUND VALUE: %s" % tco.cellpath_norm)

                # Add in matched annotation, append matched PCO, specify hive
                tco.annos = {"matched"}
                tco.original_cellobject = pco
                tco.active_hive = self.active_hive

                # Log matched entries, append matched TCO to matches
                logging.info("  > VALUE HARD: %s\t%s" % (tco.cellpath,
                                                         tco.alloc))
                logging.info("                %s\t%s\t%s\t%s" % (pco.app_name,
                                                                 pco.app_state,
                                                                 pco.cellpath_norm,
                                                                 pco.alloc))
                self.matches.append(tco)
                self.matches_count += 1
                return

            # Soft match: path, data type, allocation
            elif (match_cell_path(tco, pco) and
                  match_data_type(tco, pco) and
                  match_cell_alloc(tco, pco)):
                ##print("FOUND SOFT VALUE: %s" % tco.cellpath_norm)

                # Add in matched annotation, append matched PCO, specify hive
                tco.annos = {"matched_soft"}
                tco.original_cellobject = pco
                tco.active_hive = self.active_hive

                # Log matched entries, append matched TCO to matches
                logging.info("  > VALUE SOFT: %s\t%s" % (tco.cellpath,
                                                         tco.alloc))
                logging.info("                %s\t%s\t%s\t%s" % (pco.app_name,
                                                                 pco.app_state,
                                                                 pco.cellpath_norm,
                                                                 pco.alloc))
                self.matches.append(tco)
                self.matches_count += 1
                return

    def results(self):
        """ Print overview of results to log file. """

        # Log results overview
        logging.info("\n\n>>> Windows Registry Analysis Overview:")
        profile_states = [pco.app_state for pco in self.pcos]
        target_states = [tco.original_cellobject.app_state for tco in self.matches]
        for state in set(profile_states):
            logging.info("    {0:<20s} {1:5d} {2:10d}".format(state,
                                                       profile_states.count(state),
                                                       target_states.count(state)))

        # Provide more detailed results, log a list of:
        # 1) Detected results (app, state, path)
        # 2) Not Detected results (app, state, path)
        found = list()
        notfound = list()

        # Compare all PCOs against matched PCOs
        # Get a list of found PCOs
        # Get a list of notfound PCOs
        for pco in self.pco_regxml:
            a_match = False
            for tco in self.matches:
                diffs = Objects.CellObject.compare_to_other(pco,
                                                            tco.original_cellobject,
                                                            ignore_properties = {"cellpath, basename"})
                if not diffs:
                    found.append(pco)
                    a_match = True
            if not a_match:
                notfound.append(pco)

        # Log found PCOs
        logging.info("\n>>> Windows Registry Entries - Detected: %d" % len(found))
        for pco in found:
            logging.info("    %s\t%s\t%s\t%s" % (pco.app_name,
                                                 pco.app_state,
                                                 pco.name_type,
                                                 pco.cellpath_norm))

        # Log notfound PCOs
        logging.info("\n>>> Windows Registry Entries - NOT Detected: %d" % len(notfound))
        for pco in notfound:
            logging.info("    %s\t%s\t%s\t%s" % (pco.app_name,
                                                 pco.app_state,
                                                 pco.name_type,
                                                 pco.cellpath_norm))

        # Print overview of results based on application state and hive file
        ins_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "install"]
        ins_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "install"]
        ins_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "install"]

        ope_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "open"]
        ope_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "open"]
        ope_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "open"]

        clo_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "closed"]
        clo_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "closed"]
        clo_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "closed"]

        uni_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "uninstall"]
        uni_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "uninstall"]
        uni_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "uninstall"]

        total_ins = len(ins_ntu) + len(ins_sof) + len(ins_sys)
        total_ope = len(ope_ntu) + len(ope_sof) + len(ope_sys)
        total_clo = len(clo_ntu) + len(clo_sof) + len(clo_sys)
        total_uni = len(uni_ntu) + len(uni_sof) + len(uni_sys)

        logging.info("\n>>> Windows Registry Analysis Overview:")
        logging.info("    {0:<12s} {1:<8s} {2:<8s} {3:<8s} {4:<8s}".format("Hive",
                                                   "Install",
                                                   "Open",
                                                   "Close",
                                                   "Uninstall"))
        logging.info("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("SOFTWARE",
                                                   len(ins_sof),
                                                   len(ope_sof),
                                                   len(clo_sof),
                                                   len(uni_sof)))
        logging.info("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("SYSTEM",
                                                   len(ins_sys),
                                                   len(ope_sys),
                                                   len(clo_sys),
                                                   len(uni_sys)))
        logging.info("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("NTUSER",
                                                   len(ins_ntu),
                                                   len(ope_ntu),
                                                   len(clo_ntu),
                                                   len(uni_ntu)))
        logging.info("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("TOTAL",
                                                   total_ins,
                                                   total_ope,
                                                   total_clo,
                                                   total_uni))


    def results_overview(self):
        """ Print overview of results to console. """

        # Log results overview
        print("\n\n>>> Windows Registry Analysis Overview:")
        profile_states = [pco.app_state for pco in self.pcos]
        target_states = [tco.original_cellobject.app_state for tco in self.matches]
        for state in set(profile_states):
            print("    {0:<20s} {1:5d} {2:10d}".format(state,
                                                       profile_states.count(state),
                                                       target_states.count(state)))
        return
        # Print overview of results based on application state and hive file
        ins_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "install"]
        ins_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "install"]
        ins_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "install"]

        ope_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "open"]
        ope_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "open"]
        ope_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "open"]

        clo_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "closed"]
        clo_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "closed"]
        clo_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "closed"]

        uni_sof = [tco for tco in self.matches if tco.rootkey == "SOFTWARE" and tco.original_cellobject.app_state == "uninstall"]
        uni_sys = [tco for tco in self.matches if tco.rootkey == "SYSTEM" and tco.original_cellobject.app_state == "uninstall"]
        uni_ntu = [tco for tco in self.matches if tco.rootkey == "NTUSER.DAT" and tco.original_cellobject.app_state == "uninstall"]

        total_ins = len(ins_ntu) + len(ins_sof) + len(ins_sys)
        total_ope = len(ope_ntu) + len(ope_sof) + len(ope_sys)
        total_clo = len(clo_ntu) + len(clo_sof) + len(clo_sys)
        total_uni = len(uni_ntu) + len(uni_sof) + len(uni_sys)

        print(">>> Windows Registry Analysis Overview:")
        print("    {0:<12s} {1:<8s} {2:<8s} {3:<8s} {4:<8s}".format("Hive",
                                                   "Install",
                                                   "Open",
                                                   "Close",
                                                   "Uninstall"))
        print("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("SOFTWARE",
                                                   len(ins_sof),
                                                   len(ope_sof),
                                                   len(clo_sof),
                                                   len(uni_sof)))
        print("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("SYSTEM",
                                                   len(ins_sys),
                                                   len(ope_sys),
                                                   len(clo_sys),
                                                   len(uni_sys)))
        print("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("NTUSER",
                                                   len(ins_ntu),
                                                   len(ope_ntu),
                                                   len(clo_ntu),
                                                   len(uni_ntu)))
        print("    {0:<12s} {1:<8d} {2:<8d} {3:<8d} {4:<8d}".format("TOTAL",
                                                   total_ins,
                                                   total_ope,
                                                   total_clo,
                                                   total_uni))

    def regxml_report(self):
        """ Create a RegXML document with all matched Registry entries. """

        # Create a HiveObject to append matched cells
        hives = dict()

        # Determine source hive files where matches were found
        hive_filenames = {tco.active_hive for tco in self.matches}

        # Create a hive object for each source hive file
        for hive_filename in hive_filenames:
            hives[hive_filename] = Objects.HiveObject(filename=hive_filename)

        # Append matched CellObjects to the correct target hive
        for hive_filename in hives:
            for tco in self.matches:
                if hive_filename == tco.active_hive:
                    hives[hive_filename].append(tco)

        # Create a RegXMLObject
        regxml = Objects.RegXMLObject()

        # Add XML Name Space for "delta" attribute to RegXMLObject
        XMLNS_DELTA = "http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing"
        regxml.add_namespace("delta", XMLNS_DELTA)

        # Append each HiveObject to the RegXMLObject
        for hive_filename in hives:
            regxml.append(hives[hive_filename])

        # Make a RegXML document
        report_name = self.outputdir + "/RegistryMatching.reg.xml"
        logging.info("\n>>> RegXML REPORT: %s" % report_name)

        # Python 2 portability problem. If using Python 2, decode the to_regxml()
        # string output to unicode and store in a Python StringIO object.
        # If Python 3, just create a Python StringIO object
        if sys.version_info < (3, 0):
            temp_xml = regxml.to_regxml().decode("unicode-escape")
            temp_report = io.StringIO(temp_xml)
        else:
            temp_report = io.StringIO(regxml.to_regxml())

        # Read StingIO file using minidom, then pretty print output
        xml_fi = xml.dom.minidom.parse(temp_report)
        with open(report_name, 'w') as f:
            f.write(xml_fi.toprettyxml(indent="  "))
        f.close()

################################################################################
################################################################################
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description='''RegistryProcessing.py''', formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("imagefile",
                        help = "Target disk image")
    parser.add_argument('outputdir',
                        action = 'store',
                        help = 'Output directory')
    parser.add_argument("apxmls",
                        help = "Application Profile XML document(s)",
                        nargs = '+')
    parser.add_argument("--dfxml",
                        metavar = 'DFXML',
                        action = 'store',
                        help = "DFXML report previously generated using fiwalk")
    parser.add_argument("--hives",
                        metavar = 'HIVES',
                        action = 'store',
                        help = "Directory of hive files previously extracted using hivexml")
    parser.add_argument("-d",
                        help = "Do not remove files ending with '/.' and '/..' \n(default is to remove these files)",
                        action = "store_false",
                        default = True)
    parser.add_argument("-t",
                        help = "Report all timestamps in Unix timestamp format \n(default timestamp format is ISO 8601)",
                        action="store_true")

    args = parser.parse_args()

    # Parse command line arguments
    imagefile = os.path.abspath(args.imagefile)
    outputdir = os.path.abspath(args.outputdir)
    profiles = args.apxmls
    xmlfile = args.dfxml
    hives_dir = args.hives
    ignore_dotdirs = args.d
    timestamp = args.t
    zapdir = args.z

    ###################################
    # Perform Windows Registry analysis
    ###################################
    reg = RegistryProcessing.RegistryProcessing(imagefile = imagefile,
                                                xmlfile = xmlfile,
                                                outputdir = outputdir,
                                                profiles = profiles,
                                                hives_dir = hives_dir,
                                                timestamp = timestamp)
    reg.process_apxmls()
    reg.parse_target()
    reg.regxml_report()
    reg.results()
