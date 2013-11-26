from pprint import pformat
from twisted.internet import reactor
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.internet import task
from twisted.internet import defer
import socket

def doWork(filename, port=80):
    agent = Agent(reactor, 1)
    with open(filename, "r") as f:
        for ip in f.readlines():
            url = "http://" + ip + ":" + str(port)
            d = agent.request(
            'GET',                                           \
             url,                  \
              None)
            d.addCallback(cbResponse, ip)
            d.addErrback(cbError)
            reactor.callLater(1, d.cancel)
            yield d

def cbResponse(ignored, ip):
    print "***********************************"
    print ip
    print pformat(list(ignored.headers.getAllRawHeaders()))
    print "***********************************"

def cbError(reason):
    print reason

def cbShutdown(ignored):
    print "Task is over!"
    reactor.callLater(5, reactor.stop)

def mainTask():
    import sys
    deferreds = []
    coop = task.Cooperator()
    if len(sys.argv) == 2:
        work = doWork(sys.argv[1])
    else:
        print "Error!"
        sys.exit()
    maxRun = 2048
    for i in xrange(maxRun):
        d = coop.coiterate(work)
        deferreds.append(d)
    dl = defer.DeferredList(deferreds, consumeErrors=True).addCallback(cbShutdown)

if __name__ == "__main__":
    import os
    os.system("ulimit -n 4096")
    mainTask()
    reactor.run()
