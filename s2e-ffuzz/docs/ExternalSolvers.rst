=================================
Using External Constraint Solvers
=================================

S2E uses the built-in STP solver by default, which provides good performance for a variety of programs.

However, if a given test generates queries that are too hard for STP to solve, it is possible
to use other constraint solvers, such as Z3.

S2E provides a service-like interface to interact with other solvers.
The communication between S2E and the solver is done over a socket.


Launching the Constraint Solving Service
========================================

S2E provides a sample Python script that wraps Z3's built-in shell in a simple Web interface.
The script is located in ``$S2EDIR/s2e/cs-svc/cs-svc.py``. More details about the
protocol can be found in ``$S2EDIR/s2e/cs-svc/README``.

::

    $ ./cs-svc.py -z3 '/path/to/z3' -port 1234


Configuring an External Solver
==============================

The following code snippet instructs S2E to connect to the constraint solving service
running on ``localhost:1234`` and log all the queries (``external-solver-debug``).

In addition to that, S2E will run the solver in *incremental* mode. Incremental mode
greatly speeds up the exploration of deep execution paths by not sending the whole set
of constraints on each solver query.

.. code-block:: lua

   -- File: config.lua
   s2e = {
     kleeArgs = {
       ...
       "--use-external-solver",
       "--external-solver-host=localhost",
       "--external-solver-port=1234",
       "--external-solver-incremental",
       "--external-solver-debug",
       ...
     }
   }

