#!/usr/bin/env python3

import pylokinet
from pylokinet import Context as Lokinet

from threading import Thread

import requests
import time

pylokinet.set_net_id("gamma")

def load_nodedb():
    return dict()

def store_nodedb(k, v):
    print(f'store nodedb entry: {k} {v}')

def del_nodedb_entry(k):
    print(f'delete entry from nodedb: {k}')

class Waiter(Thread):

    def __init__(self, wait_for=1000, finish=None):
        Thread.__init__(self)
        self._wait_for = wait_for
        self._work_completed = False
        self._work_over = False
        self._finished = finish

    def done(self):
        self._work_completed = True
        self.join()

    @property
    def working(self):
        return not self._work_completed and not self._work_over

    def run(self):
        time.sleep(self._wait_for)
        self._work_over = True
        if self._finished:
            self._finished(self._work_completed)

def hook(ctx, good):
    ctx.stop()
    print(f'test was {"" if good else "no"} bueno')
    assert good

def run_lokinet(wait_for, *, nodedb_class=dict, pin_hops=list(), snode="55fxrybf3jtausbnmxpgwcsz9t8qkf5pr8t5f4xyto4omjrkorpy.snode:35520"):
    ctx = Lokinet()
    waiter = Waiter(wait_for, lambda good: hook(ctx, good))
    waiter.start()
    # pin first hops
    if pin_hops:
        for hop in pin_hops:
            ctx.set_config_opt('network', 'strict-connect', hop)
        ctx.set_config_opt('router', 'min-routers', f'len(pin_hops)')
    ctx.set_config_opt('network', 'reachable', 'false')
    ctx.set_config_opt('api', 'enabled', 'false')
    ctx.set_config_opt('logging', 'level', 'info')
    ctx.set_config_opt('network', 'profiling', 'false')
    db = None
    if nodedb_class:
        db = nodedb_class()
        ctx.nodedb_load = lambda : db
        ctx.nodedb_store = db.__setitem__
        ctx.nodedb_del = db.__delitem__
    req = requests.get("https://seed.lokinet.org/testnet.signed", stream=True)
    ctx.add_bootstrap_rc(req.content)
    print("starting....")
    ctx.start()
    while not ctx.wait_for_ready(100):
        assert waiter.working
    print(f"we are {ctx.localaddr()}")
    id = None
    try:
        addr, port, id = ctx.resolve(snode, wait_for)
        print(f"resolved {snode} as {addr}:{port} on {id}")
        resp = requests.get(f"https://{addr}:{port}/", verify=False)
        print(resp.text)
    except Exception as ex:
        print(f'failed: {ex}')
    finally:
        if id:
            ctx.unresolve(id)
    waiter.done()
    del ctx
    print(f'we have {len(db)} nodedb entries left over')
    print(f'{list(db.keys())}')

if __name__ == '__main__':
    run_lokinet(30)
