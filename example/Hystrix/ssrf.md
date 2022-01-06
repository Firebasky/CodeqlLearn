# Hystrix

CVE-2020-5412

漏洞点比较简单。

![image](https://user-images.githubusercontent.com/63966847/148392353-328f1ef3-b55c-46e1-96c7-3ba94b82b38b.png)

ql实现应该和Sentinel的ssrf差不多，而且还简单不需要add操作

```ql
/**
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node src) { 
    src instanceof RemoteFlowSource//默认的
   }

   //sink  HttpGet构造方法
	override predicate isSink(DataFlow::Node sink) {
	   exists(ConstructorCall call, Class clz| 
		call.getAnArgument() = sink.asExpr()
		and call.getConstructedType()=clz 
		and clz.getName()="HttpGet"
		)
  }

}

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
```
