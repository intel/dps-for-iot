#!/usr/bin/python

from common import *
import atexit
import time

atexit.register(cleanup)

subs = [
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s B --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s G --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s A --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s C --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s D --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s F --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X -s E --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --'),
    sub('-s X --')
]

links = [
    [subs[1].port, subs[2].port, subs[3].port, subs[4].port],
    [subs[5].port, subs[6].port, subs[7].port],
    [subs[6].port, subs[21].port],
    [subs[7].port],
    [],
    [subs[8].port, subs[9].port, subs[10].port],
    [subs[9].port, subs[22].port],
    [subs[10].port],
    [subs[11].port, subs[12].port, subs[13].port],
    [subs[12].port, subs[23].port],
    [subs[13].port],
    [subs[14].port, subs[15].port, subs[16].port],
    [subs[15].port, subs[24].port],
    [subs[16].port],
    [subs[17].port, subs[18].port, subs[19].port],
    [subs[18].port, subs[25].port],
    [subs[19].port],
    [subs[2].port, subs[20].port, subs[4].port],
    [subs[20].port, subs[26].port],
    [subs[4].port],
    [subs[21].port, subs[27].port],
    [subs[22].port, subs[28].port],
    [subs[23].port, subs[29].port],
    [subs[24].port, subs[30].port],
    [subs[25].port, subs[31].port],
    [subs[26].port, subs[32].port],
    [subs[27].port, subs[33].port],
    [subs[28].port, subs[34].port],
    [subs[29].port, subs[35].port],
    [subs[30].port, subs[36].port],
    [subs[31].port, subs[37].port],
    [subs[32].port, subs[38].port],
    [subs[39].port, subs[33].port],
    [subs[40].port, subs[34].port],
    [subs[41].port, subs[35].port],
    [subs[42].port, subs[36].port],
    [subs[43].port, subs[37].port],
    [subs[44].port, subs[38].port],
    [subs[39].port, subs[45].port],
    [subs[40].port, subs[46].port],
    [subs[41].port, subs[47].port],
    [subs[42].port, subs[48].port],
    [subs[43].port, subs[3].port],
    [subs[44].port, subs[7].port],
    [subs[45].port, subs[10].port],
    [subs[46].port, subs[13].port],
    [subs[47].port, subs[16].port],
    [subs[48].port, subs[19].port],
    [subs[3].port, subs[4].port]
]

begin = time.time()
for i in range(len(subs)):
    link(subs[i], links[i])

for i in range(len(subs)):
    expect_linked(subs[i], links[i])

num_links = 0
for i in range(len(subs)):
    num_links = num_links + len(links[i])
exp_muted = (num_links + 1 - len(subs))

wait_until_settled(subs, exp_muted, 60)
end = time.time()
print('Link settling time = {} seconds'.format(end - begin))

# Routing check

for sub in subs:
    pub('-p {} A B C D E F G'.format(sub.port))

expect_pub_received([subs[5], subs[14], subs[23], subs[26], subs[32], subs[38], subs[44]],
                    ['A B C D E F G'] * len(subs))

# Reachability check

pub('-p {} X'.format(subs[41].port))

expect_pub_received(subs, 'X')
