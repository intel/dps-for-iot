#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

subs = [
    sub('1.1.#'),
    sub('1.1.#'),
    sub('1.1.#')
]

for i in range(100):
    pub('1.1.{}'.format(i))

expect_pub_received(subs, ['1.1.\d+'] * 100)
