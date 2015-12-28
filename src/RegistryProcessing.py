# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2015/12/28

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
import timeit
import glob
import hashlib
import io
import xml.dom.minidom

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

"""
try:
    import HiveExtractor
except ImportError:
    print('Error: RegistryProcessing.py')
    print('       The HiveExtractor.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/Vestigium')
    print('       Now Exiting...') 
    sys.exit(1)
"""

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
    return tco.normpath == pco.normpath

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
    return tco.data == pco.raw_data        

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
        print("\n----------------------------------------")
        print(">>> PERFORMING WINDOWS REGISTRY ANALYSIS")
        print("----------------------------------------")

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
        
        # active_hive specifies the hive name (base name) for the hive being processed
        self.active_hive = None
        
        # active_rootkey is the common root key name (SOFTWARE, SYSTEM, NTUSER.DAT)
        self.active_rootkey = None        

    def process_apxmls(self):
        """
        Method to parse the RegXML CellObjects from the
        Application Profile XML structure.
        """
        print(">>> Processing application profiles ...")
        logging.info("\n>>> Application profile information:")

        # Process each target Application Profile XML (APXML) document
        for profile in self.profiles:
            print("  > Processing %s" % os.path.basename(profile))
            apxml_obj = apxml.iterparse(profile)
            apxml.generate_stats(apxml_obj)
            for pco in apxml_obj:
                if isinstance(pco, Objects.CellObject):
                    # Normalize the cellpath path and append to CellObject
                    pco.normpath = self.cell_path_normalizer.normalize_profile_co(pco.cellpath)
                    rootkey = pco.normpath.split("\\")[0]
                    pco.normpath = self.cell_path_normalizer.normalize_target_co(pco.normpath, rootkey)
                    
                    # Normalize the basename
                    pco.normbasename = None
                    if pco.basename and pco.basename.startswith("C:"):
                        normbasename = self.file_path_normalizer.normalize(pco.basename)
                        normbasename = normbasename.replace('/', '\\')
                        pco.normbasename = normbasename
                    
                    # Append application name to CellObject
                    pco.app_name = apxml_obj.metadata.app_name
                    
                    # Add Profile CellObject (PCO) to:
                    # 1) PCO list
                    # 2) PCO dictionary
                    self.pcos.append(pco)
                    self.pcos_dict[pco.normpath].append(pco)
                    
                    if pco.name_type == "k":
                        self.pcos_keys[pco.normpath].append(pco)
                    elif pco.name_type == "v":
                        self.pcos_values[pco.normpath].append(pco)
                    
                    # Get set of required hives based on profile entries
                    #rootkey = pco.normpath.split("\\")[0]
                    self.target_hives.add(rootkey)
                    pco.rootkey = rootkey
                    
                    # Also append PCO to a RegXML object
                    self.pco_regxml.append(pco)
                    
                    # Log all profile entries (Application, State, Path)
                    logging.info("    %s\t%s\t%s" % (apxml_obj.metadata.app_name,
                                                     pco.state,
                                                     pco.normpath))
                                                     
        # Log all target hive names (rootkey)
        logging.info("\n>>> Target Registry hives:")
        for rootkey in self.target_hives:
            logging.info("  > %s" % rootkey)

    def parse_target(self):
        """
        Introduce.
        """
        print("\n>>> Processing target hives ...")
        
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
                
        for rootkey in self.target_hives:
            #print(rootkey)
            #if rootkey == "NTUSER.DAT" or rootkey == "SOFTWARE":
            #    continue
                      
            for hive in self.to_process[rootkey]:
                #print("  > %s" % os.path.basename(hive))
                self.active_hive = hive
                self.active_rootkey = rootkey
                
                for (event, obj) in Objects.iterparse_CellObjects(hive):
                    if isinstance(obj, Objects.CellObject):
                        #print(obj.cellpath)
                        obj.rootkey = rootkey
                        self.process_target_co(obj)

    def process_target_co(self, tco):
        """ Process each Target CellObject (TCO). """    
        
        # Registry count progress indicator
        if tco.name_type == 'k':
            self.target_key_count += 1
        elif tco.name_type == 'v':
            self.target_value_count += 1
        sys.stdout.write("\r  > Keys: {0:6}  Values: {1:6}".format(self.target_key_count, self.target_value_count));
            
        # Normalize the TCO rootkey
        tco.normpath = self.cell_path_normalizer.normalize_target_co_rootkey(tco.cellpath, self.active_rootkey)
        
        # Normlaize the TCO cell path (full path)
        tco.normpath = self.cell_path_normalizer.normalize_target_co(tco.normpath, self.active_rootkey)
        
        # Normalize the basename
        tco.normbasename = None
        if tco.basename and tco.basename.startswith("C:"):
            normbasename = self.file_path_normalizer.normalize(tco.basename)
            normbasename = normbasename.replace('/', '\\')
            tco.normbasename = normbasename
        
        if tco.name_type == 'k':
            if tco.normpath in self.pcos_keys:
                for pco in self.pcos_keys[tco.normpath]:
                    self.match_tco_pco(tco, pco)
                
        if tco.name_type == 'v':
            if tco.normpath in self.pcos_values:
                for pco in self.pcos_values[tco.normpath]:
                    self.match_tco_pco(tco, pco)
                    
        # Perform a cell path lookup in self.pcos_dict
        # If a match is found, process further using match_tco_pco()
        #for pco in self.pcos:
        #    if pco.name_type == tco.name_type:
        #        if pco.rootkey == tco.rootkey:
        #            if pco.alloc == tco.alloc:
        #                self.match_tco_pco(tco, pco)
        
        # CANT DO A PATH LOOKUP WITH A BASENAME PROBLEM                        
                      
        #if tco.normpath in self.pcos_dict:
        #    for pco in self.pcos_dict[tco.normpath]:
        #        if pco.rootkey == tco.rootkey:
        #            self.match_tco_pco(tco, pco)

    def match_tco_pco(self, tco, pco):
        """ Match the target cellobject to the profile cellobject. """
        
        # If tco and pco are different types (key or value) return
        if not match_cell_type(tco, pco):
            return
        
        # Match Registry key (path, allocation)
        if tco.name_type == "k":
            if (match_cell_path(tco, pco) and 
                match_cell_alloc(tco, pco)):
                ##print("FOUND KEY: %s" % tco.normpath)
                
                # Add in matched annotation, append matched PCO
                tco.annos = {"matched"}
                tco.original_cellobject = pco
                tco.active_hive = self.active_hive
                # Log matched entries, append matched TCO to matches
                logging.info("  > KEY: %s\t%s" % (tco.cellpath, 
                                                  tco.alloc))
                logging.info("         %s\t%s\t%s\t%s" % (pco.app_name,
                                                          pco.state,
                                                          pco.normpath,
                                                          pco.alloc))
                self.matches.append(tco)
                return
        
        # Match Registry value 
        elif tco.name_type == "v":
            
            # Hard match: path, data type, actual data, allocation
            if (match_cell_path(tco, pco) and
                match_data_type(tco, pco) and
                match_data(tco, pco) and 
                match_cell_alloc(tco, pco)):
                ##print("FOUND VALUE: %s" % tco.normpath)
                
                # Add in matched annotation, append matched PCO
                tco.annos = {"matched"}
                tco.original_cellobject = pco
                tco.active_hive = self.active_hive
                
                # Log matched entries, append matched TCO to matches
                logging.info("  > VALUE: %s\t%s" % (tco.cellpath, 
                                                    tco.alloc))
                logging.info("           %s\t%s\t%s\t%s" % (pco.app_name,
                                                            pco.state,
                                                            pco.normpath,
                                                            pco.alloc))
                self.matches.append(tco)
                return
            
            # Soft match: path, data type, allocation
            elif (match_cell_path(tco, pco) and
                  match_data_type(tco, pco) and
                  match_cell_alloc(tco, pco)):
                ##print("FOUND SOFT VALUE: %s" % tco.normpath)
                
                # Add in matched annotation, append matched PCO, active hive file name
                tco.annos = {"matched_soft"}
                tco.original_cellobject = pco
                tco.active_hive = self.active_hive
                
                # Log matched entries, append matched TCO to matches
                logging.info("  > VALUE: %s\t%s" % (tco.cellpath, 
                                                    tco.alloc))
                logging.info("           %s\t%s\t%s\t%s" % (pco.app_name,
                                                            pco.state,
                                                            pco.normpath,
                                                            pco.alloc))
                self.matches.append(tco)
                return

    def results(self):
        # Provide overview of results
        print("\n>>> Windows Registry Analysis Overview:")    
        profile_states = [pco.state for pco in self.pcos]
        target_states = [tco.original_cellobject.state for tco in self.matches]
        for state in set(profile_states):
            print("    {0:<20s} {1:5d} {2:10d}".format(state,
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
                diffs = Objects.CellObject.compare_to_other(pco, tco.original_cellobject)
                if not diffs:
                    found.append(pco)
                    a_match = True
            if not a_match:
                notfound.append(pco)
                  
        # Log found PCOs  
        logging.info("\n>>> Windows Registry Entries - Detected:")
        logging.info("  > Total: %d" % len(found))
        for pco in found:
            logging.info("    %s\t%s\t%s" % (pco.app_name, pco.state, pco.normpath))

        # Log notfound PCOs
        logging.info("\n>>> Windows Registry Entries - NOT Detected:")
        logging.info("  > Total: %d" % len(notfound))
        for pco in notfound:
            logging.info("    %s\t%s\t%s" % (pco.app_name, pco.state, pco.normpath))


    def results_overview(self):
        """  """
        # NOT FOUND
        matched_cellpaths = [tco.normpath for tco in self.matches]
        profile_cellpaths = [pco.normpath for pcos in self.pcos.values() for pco in pcos]
        #print(matched_cellpaths)
        #print(profile_cellpaths)
        diff = set(profile_cellpaths) - set(matched_cellpaths)
        diff = sorted(diff)
        logging.info("\n>>> NOT DETECTED WINDOWS REGISTRY ARTIFACTS:")
        for path in diff:
            logging.info("    %s" % path)
        # Provide an overview of results
        matched_states = [tco.state for tco in self.matches]
        profile_states = [pco.state for pcos in self.pcos.values() for pco in pcos]
        print("\n>>> Windows Registry Analysis Overview:")
        print("    {0:<20s} {1:8s} {2:10s}".format("Applicaiton State", "Profile", "Discovered"))
        print("    {0:<20s} {1:5d} {2:10d}".format("Install", profile_states.count("install"), matched_states.count("install")))
        print("    {0:<20s} {1:5d} {2:10d}".format("Open", profile_states.count("open"), matched_states.count("open")))
        print("    {0:<20s} {1:5d} {2:10d}".format("Close", profile_states.count("close"), matched_states.count("close")))
        print("    {0:<20s} {1:5d} {2:10d}".format("Uninstall", profile_states.count("uninstall") , matched_states.count("uninstall")))
        print()
        logging.info("\n>>> Windows Registry Analysis Overview:")
        logging.info("    {0:<20s} {1:8s} {2:10s}".format("Applicaiton State", "Profile", "Discovered"))
        logging.info("    {0:<20s} {1:5d} {2:10d}".format("Install", profile_states.count("install"), matched_states.count("install")))
        logging.info("    {0:<20s} {1:5d} {2:10d}".format("Open", profile_states.count("open"), matched_states.count("open")))
        logging.info("    {0:<20s} {1:5d} {2:10d}".format("Close", profile_states.count("close"), matched_states.count("close")))        
        logging.info("    {0:<20s} {1:5d} {2:10d}".format("Uninstall", profile_states.count("uninstall") , matched_states.count("uninstall")))
        #
        matched_hives = [tco.rootkey for tco in self.matches]
        software = matched_hives.count("SOFTWARE")
        system = matched_hives.count("SYSTEM")
        ntuserdat = matched_hives.count("NTUSER.DAT")
        profile_hives = [pco.rootkey for pcos in self.pcos.values() for pco in pcos]
        print("    {0:<20s} {1:8s} {2:10s}".format("Registry Hive", "Profile", "Discovered"))
        print("    {0:<20s} {1:5d} {2:10d}".format("Software", profile_hives.count("SOFTWARE"), software))
        print("    {0:<20s} {1:5d} {2:10d}".format("System", profile_hives.count("SYSTEM"), system))
        print("    {0:<20s} {1:5d} {2:10d}".format("ntuser.dat", profile_hives.count("NTUSER.DAT"), ntuserdat))
        print()

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
    parser = argparse.ArgumentParser(description='''''')
    parser.add_argument("imagefile",
                        help = "Target disk image (e.g. target.E01)")
    parser.add_argument("xmlfile",
                        help = "DFXML report generated by fiwalk (e.g. target.dfxml)")
    parser.add_argument('regxml_dir',
                        help = 'RegXML report directory')
    parser.add_argument('outputdir',
                        help = 'Output directory')
    parser.add_argument("profiles",
                        help = "Application Profile XML profile file (e.g. TrueCrypt.ap.xml)",
                        nargs = '+')
    parser.add_argument("-d",
                        help = "Do not remove files ending with '/.' and '/..' (default is to remove these files)",
                        action = "store_false",
                        default = True)
    parser.add_argument("-t",
                        help = "Report all timestamps in Unix timestamp format (default timestamp format is ISO 8601)",
                        action="store_true")
    args = parser.parse_args()

    imagefile = args.imagefile
    xmlfile = args.xmlfile
    regxml_dir = args.regxml_dir
    outputdir = args.outputdir
    profiles = args.profiles
    ignore_dotdirs = args.d
    timestamp = args.t

    ###################################
    # Perform Windows Registry analysis
    ###################################
    start_time = timeit.default_timer()
    # Create DiskState object
    regm = RegistryMatching(imagefile = imagefile,
                            xmlfile = xmlfile,
                            regxml_dir = regxml_dir,
                            profiles = profiles,
                            outputdir = outputdir,
                            timestamp = timestamp)
    regm.process_profile()
    regm.process_target()
    regm.results_overview()
    regm.dfxml_report()
    elapsed = timeit.default_timer() - start_time
    logging.info("\n>>> TIME: Run time:    %s" % elapsed)
