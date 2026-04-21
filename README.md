PeAnalyis

简短描述：
> 这是一个简单的(32||64)pe文件解析工具

---

## 关键信息
- 开发环境 (IDE): Microsoft Visual Studio Community 2026 (18.5.0)
- 首选终端 Shell: powershell.exe
- 当前文件: README.md

---

## 声明
本人只是个业余爱好者,所以该项目可能存在不规范或不正确之处.
若有大佬愿指点一二,将不胜感谢,其他建议也来之不拒.

## 主要功能
- 解析 PE 头 / 区段表
- 解析导出表、导入表、重定位表
- 在控制台打印分析信息

## 项目结构
```plaintext
- main.cpp            包含了解析类的调用方式
- PeAnalyis.h		  解析类成员的定义
- PeAnalyis.cpp       解析函数的实现,具体见文件中各函数叙述(下面仅展示笔者认为需要的两个方法)
	- PeAnalyis::analyisfile 包含类整体的实现方式
	- PeAnalyis::errorcheck  对于类中执行错误的处理,并未完全实现(因为目前不需要)
```

## 环境与依赖
- 语言：C++（本人环境为C++20）
- 平台：Windows（Visual Studio Community 2026）

## 构建与运行（Visual Studio）
1. 在 Visual Studio 中打开本仓库的解决方案文件（.sln）。
2. 选择配置（Debug/Release）与架构（x86/x64）。
3. 编译并运行。

命令行示例（PowerShell）:
```powershell
# 运行示例（根据实际生成的可执行文件调整路径）
.\\Release\\PeAnalyis.exe <PE 文件路径>
```

## 使用示例
```
# 示例命令（请替换为实际可执行文件和路径）
PeAnalyis.exe D:\\path\\to\\example.dll
```
> 或者直接双击打开

## 后续版本
目前处于1.0.0版本,此后可能进行扩展更新.

## 贡献
- 欢迎提交 Issue 或 Pull Request。请在贡献前先描述您的变更目的。

---

