---
title: "Using CodeQL to detect Use After Free (UAFs)"
date: 2022-10-25
tags: [posts]
excerpt: "A codeql query to detect Use After Free (UAF)"
---

Introduction
---

As part of a research project in the cybersecurity of small satellites (cubesats / nanosats), I was in search of way to hunt for memory corruption vulnerabilities in libraries used by these devices using a semantic code analysis engine; CodeQL. The specific library I was targetting had several buffer overflow vulnerabilities previously disclosed, thus I decided to search for potential Use after Frees (UAFs). 

My approach to detecting UAFs was the following: 
1. Identifying calls to the free function and the object freed. (source) 
2. Identifying dereferences of the specific object after it was freed. (sink)

Using CodeQL's data flow path graph configuration I was able to construct a query that identifies code paths from the source to the sink indicated above. More information in how these queries work can be found here. The single piece that I was initially missing is finding dereferences after an initial call to free. 

CodeQL query used:

```
/**
 * @id 5
 * @kind path-problem
 * @name UAF
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import DataFlow::PathGraph
//import semmle.code.cpp.dataflow.TaintTracking

class Config extends DataFlow::Configuration {
    Config() { this = "Config" }

    override predicate isSource(DataFlow::Node arg) {
    exists(FunctionCall call |
        call.getArgument(0) = arg.asDefiningArgument()
        and call.getTarget().hasGlobalOrStdName("free")
    )
    }

    override predicate isSink(DataFlow::Node sink) {
        dereferenced(sink.asExpr())
    }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, Config config
where config.hasFlowPath(source, sink)
select sink, source, sink, 
"Potential use-after-free vulnerability: memory is $@ and $@.",
source, "freed here", sink, "dereferenced here"
```

- source: In our case, the source defined as an expression is the argument supplied to a 'free' function call
- sink: The sink defined as an expression is any point at which the source argument is dereferenced after being 'freed'

Note that the query shown above can be modified to include taint tracking, meaning that if another variable was assigned to 'part' of an object that was freed, it would still be detected as a sink.  


