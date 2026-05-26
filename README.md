## 微信多开助手

可以支持多账号同时自动登录的微信多开助手，可通过配置偏移适配任意4.1以上版本。

目前已经支持的版本：

- `4.1.1.19`
- `4.1.8.101`

如果没有你需要的版本，你可以查看[如何查找偏移](./find_offset.md)来自己更新偏移，全程用时应该不会超过五分钟

#### 自动查找偏移

也可以使用 `find_offset.py` 自动扫描本地 `Weixin.dll`，查找当前版本需要的偏移并写入 `config.ini`，不需要启动 x64dbg。

先安装依赖：

```powershell
python -m pip install -r requirements.txt
```

如果已经知道 `Weixin.dll` 路径，直接指定 DLL：

```powershell
python .\find_offset.py --dll "D:\path\to\Weixin.dll"
```

如果只知道微信主程序路径，也可以指定 `Weixin.exe`，脚本会自动在同目录或版本子目录中寻找 `Weixin.dll`：

```powershell
python .\find_offset.py --wechat-exe "D:\path\to\Weixin.exe"
```

也可以在 `config.ini` 的 `[weixin]` 中填写 `path`，之后直接运行：

```ini
[weixin]
path = D:\path\to\Weixin.exe
```

```powershell
python .\find_offset.py
```

如果只想预览查找结果、不修改 `config.ini`，加上 `--dry-run`：

```powershell
python .\find_offset.py --dll "D:\path\to\Weixin.dll" --dry-run
```

更详细的文章介绍：[支持多账号自动登录的微信多开软件](https://mp.weixin.qq.com/s/Uv84LKkI8qICTCiUOXFc0Q)

网盘下载地址: `https://wwbmk.lanzoue.com/b00yb1ht1a  密码: hagx`

![](./images//1.png)

#### 使用方法

打开软件，然后选择微信路径，创建快捷方式到桌面，后面就可以通过不同的快捷方式登录不同的账号，互相不影响。

#### 实现原理

首先启动微信并暂停微信，注入DLL修改内存中的互斥体名称和`global_config`字符串，hook创建互斥体函数，当微信创建互斥体完成后，恢复修改的内存字符串，移除掉hook。

这种方式应该比直接在dll上打补丁要安全一些，hook的时间很短几乎很难被检测到。

#### 感谢

- `https://github.com/zetaloop/BetterWX`
