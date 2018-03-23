#!/usr/bin/env python

import sys
import argparse
import os
import datetime

from twisted.internet import protocol, reactor
from twisted.protocols import basic
from twisted.web import static, server, resource
from twisted.web.wsgi import WSGIResource

from pyparsing import OneOrMore, nestedExpr

class SolverProcess(protocol.ProcessProtocol):
    def __init__(self, socket, session_id):
        self._socket = socket
        self._state = 0
        self._session_id = session_id

    def resetSocket(self, newSocket):
        self._socket = newSocket

    def _outputLine(self, line):
        if not self._socket:
            print "Attempting to write without a socket"
            return

        self._socket.transport.write(line + "\n")

    """The solver has just launched"""
    def connectionMade(self):
        #print "process started"
        self.lineParser = basic.LineReceiver()
        self.lineParser.delimiter = "\n"
        self.lineParser.makeConnection(None)
        self.lineParser.lineReceived = self.lineReceived

    def lineReceived(self, line):
        print ">>", line

        if line == "sat":
            self._state = 1
            self._outputLine(line)
        elif line == "unsat":
            self._outputLine(line)
        else:
            if self._state != 1:
                #This must be an error
                print ">>Not sat or unsat, must be an error"
                self.__outputLine(line)
            else:
                #Receive the solutions
                data = OneOrMore(nestedExpr()).parseString(line)
                lst = data.asList()
                #print lst
                try:
                    #[[[['select', 'arr1', ['_', 'bv1', '32']], '#x7b']]]
                    varname = lst[0][0][0][1]
                    index = lst[0][0][0][2][1]
                    concrete = lst[0][0][1]
                    result = "%s %d %d" % (varname, int(index[2:]), int(concrete[2:], 16))
                    print result
                    self._outputLine(result)
                except:
                    pass

    """The solver wrote some data on stdout"""
    def outReceived(self, data):
        #print "recout", data
        self.lineParser.dataReceived(data)

    """The solver wrote some data on stderr"""
    def errReceived(self, data):
        #print ">>", data
        self._outputLine(data)

    """The solver process exited"""
    def processEnded(self, status):
        print "Process ended", status

        if self._socket:
            self._socket.transport.loseConnection()

        if self._session_id in g_solver_instances:
            del g_solver_instances[self._session_id]


"""
g_solver_instances has the following structure:
session_id => {
  protocol => SolverProcess(self)
  process => reactor.spawnProcess(...)
  lastConnected => date
}
"""
g_solver_instances = {}

#Next session id available
g_next_session_id = long(0)

class CsService(basic.LineReceiver):
    delimiter = "\n"

    def __init__(self, z3):
        self._done = False
        self._z3 = z3
        self._state = 0
        self._session_id = None

    def _launchSolver(self, session_id):
        z3_executable = [self._z3, '-smt2', '-in']
        self._solver_protocol = SolverProcess(self, session_id)
        self._solver = reactor.spawnProcess(
                         self._solver_protocol,
                         z3_executable[0],
                         args=z3_executable)

        g_solver_instances[session_id] = {
            'protocol': self._solver_protocol,
            'process': self._solver,
            'lastConnected': None
        }

    def _initSolver(self, session_id):
        #print "connection made"
        #solver_executable = ['/home/vitaly/s2e/build-3.2-testsuite/solver/bin/solver', '--SMTLIB2']

        if session_id not in g_solver_instances:
            self._launchSolver(session_id)
        else:
            #Reconnect to the existing solver instance
            data = g_solver_instances[session_id]
            data['protocol'].resetSocket(self)
            data['lastConnected'] = None
            self._solver_protocol = data['protocol']
            self._solver = data['process']


    def lineLengthExceeded(self, line):
        print "Input line too long"
        self._solver_protocol.transport.signalProcess("KILL")

    #Wait that the client requested are new session or asked to
    #reconnect to a previous one.
    def _wait_for_init(self, line):
        data = OneOrMore(nestedExpr()).parseString(line)
        lst = data.asList()
        print "state 0:", lst
        if lst[0][0] == "get-session-id":
            global g_next_session_id
            self._session_id = g_next_session_id
            g_next_session_id += 1
            self._initSolver(self._session_id)
            self.sendLine("%d" % (self._session_id))
            self._state = 1

        elif lst[0][0] == "set-session-id":
            self._session_id = long(lst[0][1])
            #Find an existing solver instance
            if not self._session_id in g_solver_instances:
                self.sendLine("No such session");
                self.transport.loseConnection()
            else:
                self._initSolver(self._session_id)
                self.sendLine("%d" % (self._session_id))
                self._state = 1
        else:
            self.sendLine("Invalid command " + line + ", was expecting get-session-id or set-session-id")
            self.transport.loseConnection()

    #This is the main entry routine.
    #The protocol is line-oriented.
    def lineReceived(self, line):
        if self._done:
            return

        #print "Received", line

        if self._state == 0:
            self._wait_for_init(line)
            return

        #if "check-sat" in line:
        if "exit" in line:
            print "Received end of query"
            self._solver_protocol.transport.signalProcess("KILL")
            self._done = True

        self._solver_protocol.transport.write(line + "\n")


    def connectionLost(self, reason):
        if self._session_id is None:
            return

        print "Connection with client lost", reason

        #Don't kill the solver instance immediately.
        #Let it alive to give a chance to the client to reconnect to the session.
        g_solver_instances[self._session_id]['lastConnected'] = datetime.datetime.now()


class CsServiceFactory(protocol.Factory):
    def __init__(self, z3):
        self._done = False
        self._z3 = z3

    def buildProtocol(self, addr):
        return CsService(z3)


SESSION_TIMOUT = 30

#Iterates over the set of solver instances
#and kill those that have not been active for a while
def garbage_collector():
    max_time = datetime.datetime.now() - datetime.timedelta(seconds=SESSION_TIMOUT)

    to_delete = []
    for k, v in g_solver_instances.iteritems():
        #None means the instance is active
        if v['lastConnected'] is None:
            continue

        if v['lastConnected'] < max_time:
            print "Killing expired session", k
            v['protocol'].transport.signalProcess("KILL")
            to_delete += [k]

    for k in to_delete:
        del g_solver_instances[k]

    reactor.callLater(10, garbage_collector);

if __name__ == "__main__":

    argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Constraint solving service')
    parser.add_argument('-z3', metavar='path', required=True, help='Path to the Z3 executable')
    parser.add_argument('-port', metavar='number', required=True, help='Port number for the service')

    args = vars(parser.parse_args(argv))
    port = int(args['port'])
    z3 = args['z3']

    if not os.path.exists(z3):
        print z3, 'does not exist'
        exit(-1)

    reactor.listenTCP(port, CsServiceFactory(z3))
    reactor.callLater(0, garbage_collector);
    reactor.run()

