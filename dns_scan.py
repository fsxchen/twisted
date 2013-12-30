#!/usr/bin/env python
#-*- coding:utf-8 -*-

__verson__=1.0
__LastModifiedTime__ = '2013-06-28 12:00:00'

import os
import re
import time
import logging

from twisted.names.client import AXFRController
from twisted.names.dns import DNSDatagramProtocol
from twisted.names.dns import  Query
from twisted.names.dns import Name
from twisted.names.dns import TXT
from twisted.names.dns import CH
from twisted.names.dns import Message
from twisted.python.failure import Failure
from twisted.python import log
from twisted.python import failure
from twisted.names.error import DNSQueryTimeoutError

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet import task
from twisted.internet import reactor
reactor.suggestThreadPoolSize(20000)

class DnsDatagramProtocol(DNSDatagramProtocol):
    def datagramReceived(self, data, addr):
        m = Message()
        try:
            m.fromStr(data)
        except EOFError:
            logger_debug.error("Truncated packet (%d bytes) from %s" % (len(data), addr))
            return
        except:
            logger_debug.error(failure.Failure(), "Unexpected decoding error")
            return

        if m.id in self.liveMessages:
            d, canceller = self.liveMessages[m.id]
            del self.liveMessages[m.id]
            canceller.cancel()
            try:
                d.callback(m)
            except:
                logger_debug.error()
        else:
            if m.id not in self.resends:
                self.controller.messageReceived(m, self)

def get_result(result,ip):
    msg = '\t%s\trA=%d\trCode=%d\t'%(ip,result.recAv,result.rCode)

    if result.answer == 0:
        logger_error.error(msg + 'Set Q Flag,not A: secured?')     
    if len(result.queries)== 0:
        logger_error.error(msg + 'Set Null Query:not implemented')

    if len(result.answers)!= 0:      
        version = ''
        try:
            version = result.answers[0].payload.data[0]
            version = version.replace('\n','')
        except Exception, e:
            msg += '%s\t'
            logger_debug.error(msg % e)
        logger_success.critical(msg+version)
    else:
        logger_error.error(msg + 'Set Null Answer:refused')
	

def get_error(reason,ip):
    msg = '\t%s\tN/A\tN/A\t'%(ip)
    if reason.check(DNSQueryTimeoutError):
        logger_error.error(msg + 'Timed out')
    else:
        rea = reason.getErrorMessage()
        msg += ' OtherError %s\t'
        logger_error.error(msg % rea)

def release_port(arg,dns):
    dns.transport.stopListening()

    # try:
    #     if dns:
    #         dns.transport.stopListening()
    # except Exception,e:
    #     logger_debug.error(" Other Error occur in the release_port function of dns_scan.py  %s " % e)

def doWork():
    i = 1
    try:
        for ip in file(cwd+"ipList.txt"):
            msg = '\t%s\t%d\t%s'
            ip = ip.strip()
            logger_debug.info(msg%("query",i,ip))
            df = Deferred()
            name = Name('version.bind')
            axf = AXFRController(name,df)
            dns = DnsDatagramProtocol(axf)
            d = dns.query((ip,53),[Query('version.bind',TXT,CH)])
            d.addCallback(get_result,ip)
            d.addErrback(get_error,ip)
            d.addBoth(release_port,dns)
            i += 1
            yield d
    except Exception,e:
        logger_debug.error('Have some error in the function of doWork when the i is %d \t %s \n' % (i,e))

def finish(igo):
    reactor.callLater(5, reactor.stop)
    logging.shutdown()

def taskRun():
    deferreds = []
    coop = task.Cooperator()
    work = doWork()
    maxRun = 5000
    for i in xrange(maxRun):
        d = coop.coiterate(work)
        deferreds.append(d)
    dl = defer.DeferredList(deferreds, consumeErrors=True)
    dl.addCallback(finish)

def main():
    taskRun()
    reactor.run()

if __name__ == '__main__':
    cwd = os.path.dirname(os.path.realpath(__file__))+"/"
    if not os.path.isdir(cwd+'log'):
        os.mkdir(cwd+'log') 

    formatter = logging.Formatter('%(asctime)s\t%(name)s\t%(filename)s-%(lineno)s\t%(levelname)s:%(message)s', '%Y-%m-%d %H:%M:%S')

    logger_debug = logging.getLogger('debug')
    logger_debug.setLevel(logging.DEBUG)
    fh = logging.FileHandler(cwd+'log/debug-'+time.strftime('%Y%m%d%H%M',time.localtime(time.time())))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger_debug.addHandler(fh)

    logger_error = logging.getLogger('error')
    logger_error.setLevel(logging.DEBUG)
    fh = logging.FileHandler(cwd+'log/failure-'+time.strftime('%Y%m%d%H%M',time.localtime(time.time())))
    fh.setLevel(logging.ERROR)
    fh.setFormatter(formatter)
    logger_error.addHandler(fh)

    logger_success = logging.getLogger('result')
    logger_success.setLevel(logging.CRITICAL)
    fh = logging.FileHandler(cwd+'log/success-'+time.strftime('%Y%m%d%H%M',time.localtime(time.time())))
    fh.setLevel(logging.CRITICAL)
    fh.setFormatter(formatter)
    logger_success.addHandler(fh)
 
    main()
