#!/usr/bin/python

'''
first get userAccountControl properties for each user

like so: ldapsearch -H ldap://10.10.10.xxx -x -LLL -W \
 -b "dc=xxx,dc=local" "(&(objectClass=*))" name userAccountControl

exctract UACs

if interesing UAC found, enumerate this user

'''

import sys, getopt

relevant_flags = {
        "ACCOUNTDISABLE":0x0002,
        "DONT_REQUIRE_PREAUTH":0x400000,
        "NOT_DELEGATED":0x100000,
        "TRUSTED_FOR_DELEGATION":0x80000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION":0x1000000
        }

def indentFlag(uac):
   for key, value in relevant_flags.items():      
      if (value & uac):
         print("Security relevant flag found: ", key,
          " in ", uac)       


def main(argv):
   inputfile = ''
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile="])
   except getopt.GetoptError:
      print ('decodeUAC.py -i <inputfile>')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print ('decodeUAC.py -i <inputfile with userAccountControl flag list>')
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputPath = arg

   #scan all UACs provided for interesting flags
   with open(inputPath, 'r') as inFile:
       for uac in inFile.readlines():
           uac = int(uac.strip("\n"))
           indentFlag(uac)
           #decode UAC by doing bith comparison

if __name__ == "__main__":
    main(sys.argv[1:])
