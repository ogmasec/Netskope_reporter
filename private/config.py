#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import sys

###### Reading configuration file
parse = configparser.RawConfigParser()
if not parse.read('private/config.ini'):
	#logger.error('Bad configuration file - exiting')
	sys.exit(0)

