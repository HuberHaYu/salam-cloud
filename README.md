# SalamPlayer 云控

SalamPlayer 的防盗版与内测控制。App 通过国内加速线路读取 `api/v1/control.json`，用内置公钥校验 `control.json.sig`，校验不过的内容一律不采用。

- `control/gate.json`：是否向用户弹出订单号验证窗口
- `control/orders.json`：订单号的加盐 PBKDF2 哈希（仓库中没有明文订单号）
- `control/beta.json`：按版本号设置内测与截止时间

修改 `control/` 后推送（或用 SalamCloud 发布），GitHub Actions 会校验、生成并签名 `api/v1/control.json`，`serial` 每次加 1，App 只接受比上次更新的版本。
