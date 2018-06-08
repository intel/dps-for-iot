#!/usr/bin/python

from common import *
import atexit
import os

atexit.register(cleanup)

#
# When DTLS being used, security must be enabled for the ack to be
# succesfully delivered.
#
if os.environ['USE_DTLS'] == '0':
    #
    # Hello world
    #
    reset_logs()

    tutorial1 = tutorial('subscribe ack')
    tutorial2 = tutorial('publish ack')

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial2, 'payload=World{}'.format(os.linesep))

    #
    # Building a DPS network
    #
    reset_logs()

    tutorial1 = tutorial()
    tutorial2 = tutorial('-p {} subscribe ack'.format(tutorial1.port))
    tutorial3 = tutorial('-p {} publish ack'.format(tutorial1.port))

    expect(tutorial2, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial3, 'payload=World{}'.format(os.linesep))

if os.environ['USE_DTLS'] != '0':
    #
    # DTLS with pre-shared keys
    #
    reset_logs()

    tutorial1 = tutorial('-x network-psk subscribe ack')
    tutorial2 = tutorial('-p {} -x network-psk publish ack'.format(tutorial1.port))

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial2, 'payload=World{}'.format(os.linesep))

    #
    # DTLS with certificates
    #
    reset_logs()

    tutorial1 = tutorial('-x network-cert subscribe ack')
    tutorial2 = tutorial('-p {} -x network-cert publish ack'.format(tutorial1.port))

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial2, 'payload=World{}'.format(os.linesep))

if os.environ['USE_DTLS'] == '0':
    #
    # Protecting the payload - symmetric key
    #
    reset_logs()

    tutorial1 = tutorial('-x symmetric subscribe ack')
    tutorial2 = tutorial('-p {} -x symmetric publish ack'.format(tutorial1.port))

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial2, 'payload=World{}'.format(os.linesep))

    #
    # Protecting the payload - asymmetric key
    #
    reset_logs()

    tutorial1 = tutorial('-x asymmetric subscribe')
    tutorial2 = tutorial('-p {} -x asymmetric publish'.format(tutorial1.port))

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))

    #
    # Authenticating the sender - symmetric key
    #
    reset_logs()

    tutorial1 = tutorial('-x symmetric auth subscribe ack')
    tutorial2 = tutorial('-p {} -x symmetric auth publish ack'.format(tutorial1.port))

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial2, 'payload=World{}'.format(os.linesep))

    #
    # Authenticating the sender - asymmetric key
    #
    reset_logs()

    tutorial1 = tutorial('-x asymmetric auth subscribe ack')
    tutorial2 = tutorial('-p {} -x asymmetric auth publish ack'.format(tutorial1.port))

    expect(tutorial1, 'payload=Hello{}'.format(os.linesep))
    expect(tutorial2, 'payload=World{}'.format(os.linesep))
