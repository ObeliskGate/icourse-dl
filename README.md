# `icourse-dl`

简单的复旦大学 iCourse 智慧教学平台下载器

通过更精简的命令行界面, 允许大家在非校园网环境 ~~(例如我的宿舍)~~ 和各种场合的本机更自由地查询, 获取视频信息.

> 灵感来源 [LeafCreeper/Fudan_iCourse_Subscriber](https://github.com/LeafCreeper/Fudan_iCourse_Subscriber)


## 使用

### 登录: `login`

按提示输入学号和密码, 验证后保存到系统凭据库, 供后续查询和下载使用. 不保存 Cookie; 凭据库不可用时会报错, 不会退回明文存储.

```sh
icourse-dl login
```

清除已保存的凭据: `icourse-dl login --clear`.

### 查询: `search`

按名称或关键词查找课程, 显示课程 ID 和所属学期; 也可以列出某门课程的课次及课次 ID. 查询不会下载视频.

```sh
icourse-dl search courses "学习概论"
icourse-dl search lectures --course-id 19198
```

课程搜索可加 `--term 27` 限定到 2026-2027 学年第一学期, 其他已核实的学期编号见 `icourse-dl search --help`.

### 下载: `download`

按名称查找后, 交互选择学期, 课程和课次; 已知课程 ID 时直接选择课次. 上下键移动, 回车选择, Esc 取消; 只有一个候选项时自动选中.

```sh
icourse-dl download "学习概论"
icourse-dl download --course-id 19198
```

一次下载一节课, 默认保存到当前目录, 不覆盖已有成品. 用 `--output "./downloads"` 指定目录; 非交互使用时, 需同时指定 `--course-id` 和 `--lecture-id`.

### 通用选项

- `--env`: 使用当前目录的 `.env`; `--env PATH` 使用指定文件. 文件需包含 `StuId`, `UISPsw`, 覆盖本次使用的已保存凭据. 查询和下载不会另存这些凭据, 不加参数也不会自动读取 `.env`. 请勿提交凭据文件到 Git.
- `--verbose`: 显示脱敏认证日志, 便于排查问题.
- `--help`: 查看对应命令的完整参数.

从源码运行时, 在上述命令前加 `uv run`.

## 使用边界

本工具仅用于获准下载保存的教学资源. 登录和播放权限不等于下载许可. 请事先确认授权范围, 遵守学校规定, 不要擅自传播相关资源. 本说明不替代权利人的许可, 也不免除使用者应承担的责任.

以下摘自学校公布的 [《复旦大学智慧教学资源平台使用规范》](https://cfd.fudan.edu.cn/yuyue2/guifan.pdf).

第二部分 "知识产权保护", 第 1-2 页:

> 任何单位或个人使用平台资源时，必须获得权利人的明确许可，严格遵守《知识产权法》等国家法律法规及学校相关规定。未经许可，不得对平台资源进行复制、传播、修改、下载或以其它方式侵犯权利人的知识产权。

第三部分 "使用要求" 中的 "在校学生", 第 2 页:

> 在校学生可在任课教师授权范围内使用相关的平台资源，用于个人学习和研究目的。
>
> 在校学生应尊重任课教师的知识产权和劳动成果，不得将相关资源用于商业用途或非法活动，不得擅自传播、分享相关资源。

## License

本项目自有代码采用 **GPL-3.0-or-later**, 许可证全文见 [LICENSE](LICENSE). 软件代码许可不授予教学资源的下载或传播权限. 第三方组件遵循各自的许可证.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
