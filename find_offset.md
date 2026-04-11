
其实可以写一个工具来自动化查找偏移，不过手动查找也用不了什么时间，反而写这个工具得花费很多时间。

#### 准备工作

- 要适配的微信安装包
- x64dbg: `https://github.com/x64dbg/x64dbg`

#### 开始查找

先启动微信(不需要登录)，打开x64dbg选择菜单栏里的`文件`->`附加`选择刚才启动的微信

![alt text](./images/2.png)

选择`符号`然后双击weixin.dll会跳转到CPU的界面

![alt text](./images/3.png)

在CPU的界面右键`搜索`->`当前模块`->`字符串`，然后就会跳转到`引用`的界面

![alt text](./images/4.png)

先搜索`XWeChat_App_Instance_Identity_Mutex_Name`,这个`7FF96CFE0DBE`就是这个字符串的地址，你可以双击跳转过去按空格就能复制出来。

![alt text](./images/5.png)

点击菜单栏里的`帮助`->`计算器`，用这个地址减weixin.dll的地址得到的就是需要的偏移(mutex_name_offset)。

![alt text](./images/6.png)

还是这个字符串的位置一直划到下面第一个ret指令的地方，选择ret前面的第一个call所在的地址：00007FF966317836，偏移同样减去weixin.dll的基址(hook_offset)

![alt text](./images/7.png)

然后搜索`global_config`，

![alt text](./images/8.png)

这里选择最后一个，需要的地址是00007FF9662D8A02+8，+8是固定的(global_config_offset)。

![alt text](./images/9.png)

最后一个搜索`host-redirect.xml`,7FF96D7017D8-weixin.dll就是需要的host_redirect_xml_offset，至此所有偏移都已经找到了。

![alt text](./images/10.png)

更新到配置文件config.ini后重新打开软件就可以生效了
