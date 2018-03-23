#!/bin/sh

nc -q 2 localhost 1234 < test-new-session.smt2
nc -q 2 localhost 1234 < test-reconnect.smt2
