首先获取weixin.dll的基址备用，先搜索L`XWeChat_App_Instance_Identity_Mutex_Name`(宽字符串)，将搜索到的地址减去weixin.dll的基址就是mutex_name_offset偏移的值

再找到L`XWeChat_App_Instance_Identity_Mutex_Name`这个字符串地址被引用的位置，可先查找特征码(0F 10 05 ?? ?? ?? ?? 0F 11 00 0F 10 05 ?? ?? ?? ?? 0F 11 40 10 0F 10 05 ?? ?? ?? ?? 0F 11 40 20 0F 10 05 ?? ?? ?? ?? 0F 11 40 30 0F 10 05 ?? ?? ?? ?? 0F 11 40 40 66 C7 40 50 00 00 31 C9 31 D2 49 89 C0 FF 15 ?? ?? ?? ?? 48 85 C0)，然后确认搜索到的地址是否引用了该字符串，引用的位置应该是作为参数传递给CreateMutexW函数，然后在引用的位置往下查找第一个ret指令的位置，选择ret前面的第一个call所在的地址减去weixin.dll的基址就是hook_offset偏移的值

接着开始搜索字符串`global_config`，这个字符串地址被多个地方引用，可通过查找特征码(48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? 0D 00 00 00 48 C7 05 ?? ?? ?? ?? 0F 00 00 00 48 B8 67 6C 6F 62 61 6C 5F 63 48 89 05 ?? ?? ?? ?? 48 B8 6C 5F 63 6F 6E 66 69 67 48 89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ??)，然后从搜索结果筛选哪些地址引用了该字符串，并且对该字符串地址做赋值，类似下面的汇编

00007FFF75C689F1 | 48:B8 676C6F62616C5F63     | mov rax,0x635F6C61626F6C67                  |
00007FFF75C689FB | 48:8905 C6FCC208           | mov qword ptr ds:[0x7FFF7E8986C8],rax       | 00007FFF7E8986C8:"global_config"
00007FFF75C68A02 | 48:B8 6C5F636F6E666967     | mov rax,0x6769666E6F635F6C                  |
00007FFF75C68A0C | 48:8905 BAFCC208           | mov qword ptr ds:[0x7FFF7E8986CD],rax       | 00007FFF7E8986CD:"l_config"

需要的是字符'i'的地址(ascii码的十六进制是0x69)，所以是00007FFF75C68A02+8的地址减去weixin.dll的基址就是global_config_offset偏移的值

最后一个搜索`/host-redirect.xml`,字符串地址减去weixin.dll的基址就是host_redirect_xml_offset偏移的值，如果带`/`的搜不到就搜`host-redirect.xml`然后确认前一个字节是否是`/`(0x2F)

