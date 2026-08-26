# 测试服务器使用说明

## 服务器信息
- 端口：8081
- 地址：http://localhost:8081

## 测试接口

### 1. GET测试 - 显示查询参数
```bash
# 基本GET请求
curl "http://localhost:8081/test/get?id=123&name=john&age=25"

# 带中文参数的GET请求
curl "http://localhost:8081/test/get?name=张三&city=北京"
```

### 2. POST测试 - 显示JSON数据和表单参数
```bash
# POST JSON数据
curl -X POST "http://localhost:8081/test/post" \
  -H "Content-Type: application/json" \
  -d '{"user": "tyza66", "age": 25, "hobbies": ["coding", "music"]}'

# POST 表单数据
curl -X POST "http://localhost:8081/test/post" \
  -d "name=tyza66" \
  -d "email=test@example.com"

# POST 混合数据（查询参数 + JSON）
curl -X POST "http://localhost:8081/test/post?source=api&version=1.0" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello world"}'
```

### 3. PUT测试 - 显示JSON数据
```bash
# PUT JSON数据
curl -X PUT "http://localhost:8081/test/put" \
  -H "Content-Type: application/json" \
  -d '{"action": "update", "data": {"id": 1, "name": "updated"}}'
```

### 4. 通用测试 - 显示所有信息
```bash
# 任意方法的请求
curl -X PATCH "http://localhost:8081/test/all?param1=value1" \
  -H "Content-Type: application/json" \
  -H "X-Custom-Header: test" \
  -d '{"test": "data"}'
```

## 代理服务器测试

假设你的代理服务器在8080端口运行，可以这样测试：

### 通过代理访问测试服务器
```bash
# GET请求代理
curl "http://localhost:8080/proxy/get?url=127.0.0.1%3A8081%2Ftest%2Fget&params=id%3D123%26name%3Djohn"

# POST请求代理
curl -X GET "http://localhost:8080/proxy/post" \
  -d "url=127.0.0.1:8081/test/post" \
  -d "params=source=proxy" \
  -H "Content-Type: application/json"
```

## 响应格式示例

### GET响应示例：
```json
{
  "method": "GET",
  "timestamp": "2025-09-27 14:30:45",
  "params": {
    "id": ["123"],
    "name": ["john"]
  },
  "message": "GET request received successfully",
  "id": "123",
  "name": "john"
}
```

### POST响应示例：
```json
{
  "method": "POST",
  "timestamp": "2025-09-27 14:30:45",
  "message": "POST request received successfully",
  "queryParams": {},
  "formParams": {},
  "rawBody": "{\"user\": \"tyza66\", \"age\": 25}",
  "jsonData": {
    "user": "tyza66",
    "age": 25
  }
}
```