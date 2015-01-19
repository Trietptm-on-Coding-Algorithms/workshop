#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
{fileheader}
import sys

# https://gist.github.com/zeroSteiner/7920683
import jarvis

__version__ = '0.1'

def main():
	jar = jarvis.Jarvis()
	parser = jar.build_argparser('', version=__version__)
	args = parser.parse_args()

	return 0

if __name__ == '__main__':
	sys.exit(main())
