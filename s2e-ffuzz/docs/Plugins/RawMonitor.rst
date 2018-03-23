==========
RawMonitor
==========

The RawMonitor plugin lets users specify via a custom instruction whenever a module of interest is loaded or unloaded.
It is useful when using S2E on a new OS for which there is no plugin that automatically extracts this information.
RawMonitor can also be used to analyze raw pieces of code, such as the BIOS, firmware, etc.


Custom Instruction
------------------

Raw monitor defines the following custom instruction (in the ``rawmonitor.h`` header):

.. code-block:: c

   void s2e_raw_monitor_load_module(const S2E_RAWMONITOR_MODULE_LOAD *module);

It takes as parameter a pointer to a structure that describes the loaded module.
Use this function in your code to manually specify module boundaries, like this:

.. code-block:: c

    int main() {
      S2E_RAWMONITOR_MODULE_LOAD m;
      m.name = (uintptr_t) "myprog";
      m.path = (uintptr_t) "/home/user/myprog";
      m.pid = getpid();
      m.loadBase = ... ; /* the address where myprog is loaded */
      m.size = ... ; /* size of myprog */
      m.entryPoint = 0;
      m.nativeBase = 0;
      m.kernelMode = 0;

      s2e_raw_monitor_load_module(&m);
      ...
    }


Options
-------

The preferred way of using RawMonitor is through the ``s2e_raw_monitor*`` custom
instructions, without specifying any module descriptor in the configuration.
The ``init_env`` shared library uses this mechanism to provide basic Linux monitoring capabilities.


RawMonitor also accepts global options and an arbitrary number of per-module sections.
Per-module options are prefixed with "module." in the documentation. This can be
useful to monitor modules loaded at known fixed addresses (e.g., kernel, BIOS, etc.).

kernelStart=[address]
~~~~~~~~~~~~~~~~~~~~~
Indicates the boundary between the memory mapped in all address spaces
and process-specific memory. On Linux, this value is typically 0xC0000000, while
one Windows it is 0x80000000. Set the value to zero if this distinction
does not make sense (e.g., there are no address spaces).


module.name=["string"]
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The name of the module. This must match the name passed to ``s2e_raw_monitor_load_module``.


module.start=[address]
~~~~~~~~~~~~~~~~~~~~~~
The run-time address of the module. Set to zero if the runtime address is determined
by the custom instruction.

module.size=[integer]
~~~~~~~~~~~~~~~~~~~~~
The size of the module binary.


module.nativebase=[address]
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The default base address of the binary set by the linker.


module.kernel=[true|false]
~~~~~~~~~~~~~~~~~~~~~~~~~~
Whether the module lies above or below the kernel-mode threshold.
Assumes that the module is mapped in all address space at the same location above
the kernel/user-space boundary.



Configuration Sample
--------------------

::

    -- The custom instruction will notify RawMonitor of all newly loaded modules
    pluginsConfig.RawMonitor = {
        kernelStart = 0xc0000000,
    }
