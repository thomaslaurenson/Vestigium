# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2015/12/28

Description:
Vestigium is a proof of concept implementation of an application  profiling 
framework. The framework automates the detection of file system  and Windows 
Registry entries. All digital artifacts associated with an application are 
represented and processing automated by using the standardised DFXML, RegXML 
and APXML forensic data abstractions. 
Vestigium requires three inputs:
    1) Forensic image
    2) Output directory
    3) Application Profile XML (APXML) document(s)
    
USAGE EXAMPLE:
python3.4 Vestigium.py ~/TDS/1-install.raw /
                       ~/TDS/1-install-output /
                       ~/TDS/TrueCrypt-7.1a-6.1.7601-FINAL.apxml /
                       --dfxml ~/TDS/1-install.xml /
                       --hives ~/TDS/1-install/

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

import sys
import os
import timeit
import errno
import shutil
import glob
import logging
import datetime
import hashlib

# Append needed library paths
sys.path.append(r'src/')
sys.path.append(r'dfxml/')    
sys.path.append(r'apxml/')

try:
    import FileSystemProcessing
except ImportError:
    print('Error: Vestigium.py')
    print('       The FileSystemProcessing.py module is required.')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import RegistryProcessing
except ImportError:
    print('Error: Vestigium.py')
    print('       The RegistryProcessing.py module is required.')
    print('       Now Exiting...')
    sys.exit(1)

if sys.version_info <= (3,0):
    raise RuntimeError("Vestigium.py requires Python 3.0 or above")

################################################################################
################################################################################
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description='''
Vestigium is a proof of concept implementation of an application  profiling 
framework. The framework automates the detection of file system  and Windows 
Registry entries. All digital artifacts associated with an application are 
represented and processing automated by using the standardised DFXML, RegXML 
and APXML forensic data abstractions. 
Vestigium requires three inputs:
    1) Forensic image
    2) Output directory
    3) Application Profile XML (APXML) document(s)
    
USAGE EXAMPLE:
python3.4 Vestigium.py ~/TDS/1-install.raw /
                       ~/TDS/1-install-output /
                       ~/TDS/TrueCrypt-7.1a-6.1.7601-FINAL.apxml /
                       --dfxml ~/TDS/1-install.xml /
                       --hives ~/TDS/1-install/''', formatter_class = argparse.RawTextHelpFormatter)
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
    parser.add_argument("-z",
                        help = "Zap (delete) the output directory if it exists",
                        action = "store_true",
                        default = False)

    args = parser.parse_args()

    # Start Vestigium timer
    base_start_time = timeit.default_timer()

    # Parse command line arguments
    imagefile = os.path.abspath(args.imagefile)
    outputdir = os.path.abspath(args.outputdir)
    profiles = args.apxmls
    xmlfile = args.dfxml
    hives_dir = args.hives
    ignore_dotdirs = args.d
    timestamp = args.t
    zapdir = args.z

    # Create output folder (with error checking)
    if os.path.exists(outputdir) and os.path.isdir(outputdir):
        if zapdir:
            print('  > Error: The specified output directory already exists...')
            print('    %s' % outputdir)
            delete = input('  > Delete the existing directory? ([Y] or N): ')
            if delete.lower() == 'y' or delete.lower() == 'yes':
                shutil.rmtree(outputdir)
                os.makedirs(outputdir)
        else:
            print('  > Error: The specified output directory already exists...')
            print('    %s' % outputdir)
            print('    Quitting...')
            quit()
    else:
        os.makedirs(outputdir)

    # Set up logging, and write case information
    log = outputdir + "/vestigium.log"
    logging.basicConfig(filename = log,
                        level=logging.DEBUG,
                        format = '%(message)s')
    logging.info("Starting processing ...")
    logging.info("Start time: %s" % datetime.datetime.now())
    logging.info("\n>>> CASE INPUT INFORMATION:")
    logging.info("    Imagefile:        %s" % imagefile)
    logging.info("    Output (dir):     %s" % outputdir)
    logging.info("    Profile:          %s" % ', '.join(profiles))
    logging.info("    DFXML:            %s" % xmlfile)
    logging.info("    RegXML (dir):     %s" % hives_dir)
    logging.info("    Log file:         %s" % log)
    logging.info("    Ignore dotdirs:   %s" % ignore_dotdirs)
    logging.info("    Timestamp:        %s" % timestamp)
    logging.info("    Zap Output (dir): %s" % zapdir)

    #"""
    ##############################
    # Perform file system analysis
    ##############################
    start_time = timeit.default_timer()
    fs = FileSystemProcessing.FileSystemProcessing(imagefile = imagefile,
                                                   xmlfile = xmlfile,
                                                   outputdir = outputdir,
                                                   profiles = profiles,
                                                   ignore_dotdirs = ignore_dotdirs,
                                                   timestamp = timestamp)
    
    fs.process_apxmls()
    fs.process_target()
    fs.dfxml_report()
    fs.results()
    
    #"""
    quit()
    ###################################
    # Perform Windows Registry analysis
    ###################################
    start_time = timeit.default_timer()
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
    
    # Print overview of results
    print("\n\n-----------------------")
    print(">>> OVERVIEW OF RESULTS")
    print("-----------------------")
    #fs.results_overview()
    reg.results_overview()

    # All done, log Vestigium elapsed run time
    elapsed = timeit.default_timer() - base_start_time
    logging.info("\n>>> TIMED: Total time elapsed:    %s" % elapsed)
    
    print("\n\n>>> Finished.\n")
