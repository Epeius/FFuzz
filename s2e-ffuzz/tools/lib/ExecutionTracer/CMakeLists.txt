add_library(executiontracer STATIC CacheProfiler.cpp
                                   InstructionCounter.cpp
                                   LogParser.cpp
                                   ModuleParser.cpp
                                   PageFault.cpp
                                   PathBuilder.cpp
                                   TestCase.cpp)
