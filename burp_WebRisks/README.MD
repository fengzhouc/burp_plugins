## 更新
### 20240307
- 新增debug模式，开启debug模式会将检测的所有请求都记录下来
- 优化缓存的唯一标识,排除请求提中时间的影响
- 代码结构优化：主要是解耦、降低圈复杂度、变量优化
## 设计
1、实现IHttpListener被动扫描

2、缓存机制，扫描过的不再扫描，减少对业务的影响

3、每类问题只是轻检测，探测可疑问题，不提交大量payload，但是在告警详情里面会附上大量paylaod供手工测试或自动化跑

4、使用okhttp3实现发包器,内置任务队列/等待队列,实现更好的任务执行
## 功能介绍
![img.png](img.png)

Domain：可指定测试的域名，限制测试范围

On-Off：插件开关

ClearTable：清空数据，包含下表数据/请求缓存/已测标记/检测请求队列

Cookie：测试越权所需的他人的会话凭证cookie，会话token也可以

RefreshTable: 刷新表格数据

Scan: 批量扫描任务，会保存目标的请求，然后勾选task进行批量检测，比如检测越权IDRO_xy

Show: 显示已保存的请求信息

Clear: 清空保存的请求

右边是选择开启哪些检查项

Payload：列出漏洞的payload列表，供手工测试参考

## 可检测的漏洞
**Web Basic**
- JsonCsrf
- Cors, 会检查是否有csrftoken
- fromCsrf, 会检查是否有csrftoken
- IDOR, 未授权访问
- IDOR_xy, 横纵越权,依据你设置的cookie
- Jsonp
- Https
- Redirect
- SecureCookie
- SecureHeader, 'X-Frame-Options'
- IndexOf
- 反射型XSS
- SQL注入-字符型
- SSRF
- SensitiveApi（Swagger/SpringbootActuator/Liferay）
- SensitiveMessage, 敏感信息检测: 身份证/手机号/邮箱
- UploadSecure, 上传文件类型限制检测
- BeanParanInject, bean参数注入
- WebSocketHijacking, WebSocket的csrf攻击
- BypassAuthXFF
- Json3rd, 检测使用的json解析组件,如:fastjson
- MethodFuck, 尝试其他method是否可以请求通，有可能是同一个api不同的method
- XssDomSource, 仅检测是否有使用污染源的函数
- xml注入，比较复杂，所以仅把提交xml数据的请求识别出来，然后手搞
- SeesionInvalid，检测登出后，历史会话是否失效
- SmsEmailBoom，检测短信/邮件轰炸的业务问题，不过需要去看手机或者邮箱是否接收到大量信息

**CVE**
- LandrayOa
- ShiroUse，检测是否使用shiro
- SnoopXSS
- Spring4Shell（CVE-2022-22965）

