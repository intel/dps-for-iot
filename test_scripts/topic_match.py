#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

topic_match('No match', '-p 1/2/3 -s a/b/c')
topic_match('Match', '-p a/b/c -s a/b/c')
topic_match('Match', '-p a/b/c -p 1/2/3 -s a/b/c')
topic_match('No match', '-p a/b/c -p 1/2/3 -s +/+')
topic_match('Match', '-p a/b/c -p 1/2/3 -s +/#')
topic_match('No match', '-p a/b/c -s x/y/#')
topic_match('No match', '-p a/b/c -s +/y/#')
topic_match('Match', '-p a/b/c -s +/+/#')
topic_match('Match', '-p a/b/c -s +/+/+')
topic_match('No match', '-p a/b/c -s +/+/+/#')
