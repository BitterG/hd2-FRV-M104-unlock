# M-104 Incinerator FRV 替换 M-102 Gunner FRV 战备载具

把 **M-102 Gunner FRV(普通机枪车)战备**投下来的车换成 **M-104 Incinerator FRV(喷火车)**。

* **要装的包**:`M104-FRV-Replacer-2.3.0.zip` ← 只需这一个
* `M104-FRV-Recon-1.0.0.zip` 是**第一版纯只读侦察包**,已过时(它不会处理有嵌套数组的表)。
  想只取证不写入,请用同一个包 + 配置里 `apply = false`。

---

## 一、为什么这件事在数据上是「小改动」

工具链里的游戏明文数据镜像证实:**喷火车在这个构建里是一辆完整的车,不是要拼出来的东西**。
普通车、补给车、喷火车在实体表里是三个**独立的单位资源**:

| 变体 | 资源路径 | MurmurHash64A |
|---|---|---|
| M-102 Gunner FRV | `content/fac_helldivers/vehicles/frv/frv` | `0xcc21c7ffd3ebefb9` |
| M-103 Supply FRV | `content/fac_helldivers/vehicles/frv_supply/frv_supply` | `0x9b2140378640432e` |
| **M-104 Incinerator FRV** | **`content/fac_helldivers/vehicles/frv_heavy/frv_flamer`** | **`0x2d85bfe3d8717fe5`** |

维基对 M-104 的描述(「更重的装甲、带尖刺的撞角、车顶重型喷火器,代价是少一个座位」)
和 `frv_heavy` 那 28 张组件表记录的差异完全对得上。

战备投下哪辆车,由 `StratagemSettings` 记录里的 **`payload`** 决定(它的每一项 = 生成一个单位)。
这一条用唯一能离线读到的载具战备做了同族对照验证:两条 Exosuit(战斗步行机)记录是
`payload = [<单位哈希>, 0x75be82ed8592a6b3]`,而这几个值**每一个都真的出现在实体表的组件索引里**。

所以补丁本体只有 **8 个字节**:

```
M-102 战备记录 payload 里的 0xcc21c7ffd3ebefb9  →  0x2d85bfe3d8717fe5
```

## 二、难点不是写,是「知道该写哪一个 u64」

`generated_stratagem_settings.dl_bin`(战备表)**恰好是明文镜像没有覆盖的那一张**:
FileDiver 没有它的 parser,社区仓库这张表最后一次更新停在 **2024-10-29**(比 FRV 进游戏还早),
游戏目录里的那份是加密的(熵 7.9978,`LDLD` 出现 0 次),游戏自带 typelib 也是加密的。

所以这个 mod **不写死偏移**,而是在运行时用**内容 + 结构**把目标钉死。两个离线结论决定了做法:

**① 记录步长不能从表大小除出来。** 有嵌套数组的表,数据是 `16 + 记录数×步长 + 嵌套数据`
(编译器把嵌套数组的字节追加在记录后面)。战备表的实际载荷是 **80252** 字节,
`80236` 的因数只有 `1, 2, 4, 13, 26, 52, 1543, 3086` —— **不存在任何合理的「步长 × 记录数」组合**,
所以嵌套数据一定存在,而 `(size-16)/count` 是个假步长。
(这一条是被离线实测出来的:镜像里 `planet_override` 有 12 个实例、`weapon_customization` 有 9 个,
而 `damage/arc/beam/projectile` 这些没有嵌套数组的表,`(size-16)/count` 才正好等于步长。)

于是步长被当成**假设**:镜像 typelib 的 `StratagemInfo = 312` 是最强先验、先试,
再用记录的 `type` 列(`StratagemType` 枚举值应当是小而互不相同的整数)给每个候选打分,
**最后必须真的搜到 id 才算数**。

**② 身份判定**:1. 只在 `StratagemSettings` 表里找(按 LDLD 类型哈希 `0x30eb6399`);
2. M-102 的那个哈希必须落在**某一条记录的某个固定位置**上,而且**同一个表实例里只能出现一次**
   (多于一条 → mod 无法判断玩家说的是哪个战备 → **拒绝写入**);
   注意一张表可以编译成**多个同类 LDLD 实例**(实测 `planet_override` 12 个),所以判据是
   「每个持有该 id 的实例里只有一条记录」,而不是「记录数 == 实例数」;
3. **另一条确定在役的 FRV 战备** M-103 的哈希,必须出现在**同一张表、不同记录、同一个槽位**
   (槽位 = 记录内偏移 + 通过哪个字段到达,因为嵌套数组是间接的)。
   两条互相独立的记录对同一个槽位,才把「我找到了这几个字节」升级成「这个字段就是载具槽位」;
4. 内存里**每一份**表副本都打(同一张表在内存里有几十份,而且关卡加载会重新加载 ——
   只打一份就是经典的「一开始生效、过一会儿失效」);
5. 写之前备份原字节(内存 + 磁盘),写之后**回读校验**,之后每几秒复查一次被冲掉就重打,
   **退出时把原值放回去**。

任何一条不满足:**只写诊断、不写内存**。第一行会明说原因,`frv_m104_patch.txt` 里有完整证据,
其中一行会直接告诉你「id 到底在不在载荷里」—— 这是排查失败最有用的一条。

### 载具必须和它的「资源包」一起换(2.1 的修正,实机崩过一次)

一条战备记录不是**描述**载具,而是**点名**载具:`payload` 数组放单位哈希,**紧跟着的 `package` 字段
才是游戏去加载模型/贴图的那个资源包**,而三个 FRV 变体各有各的包。

2.0 只换了 payload。结果是**呼叫 M-102 的瞬间游戏空指针崩溃**:从崩溃转储里把原始异常挖出来看,
是 `0xC0000005` 读取地址**恰好 0x0**,位置 `game.dll+0x6F94C1`(转储里那句 `0xC0000026` 只是二次异常 ——
ntdll 在派发这个空指针时自我重入了 53 次,每帧恰好 `0xD00` 字节,这就是卡死 + WER 每 12 秒一个转储的来源)。
游戏拿着 M-102 的资源包去找喷火车的模型,取到空。

已确认**不是**「喷火车的内容没做进游戏」:游戏实体数据里 `frv_heavy/frv_flamer` 有 39 处引用
(和普通车 `frv/frv` 的 40 处同量级),而对照组 `lav`(游戏里不存在的车)是 0 处。

`package` 的偏移**不是猜的**。社区明文 dump 停在 2024-10-29(比 FRV 还早),里面没有 FRV 记录;
但它的**字段名和顺序**是准的,于是把它当标尺用:
1. 用 `id`(记录 `+4`,社区 dump 里的 `"id"`)把实时内存里的记录和社区记录配对 —— **100 条对上**;
2. 把社区记录里**每一个标量字段**的值当探针,去实时记录的 400 字节里反查偏移;
3. 结果:**100 条里 70 条的 `package` 值正好落在 `+168`**;`name_upper/+40`、`name_cased/+44`、
   `description/+48`、`fluff/+52`、`loading_loc/+56`、`uses/+80`、`denied_vo/+224`、
   `callout_vo/+232`、`spottable_vo_line/+264` 也都各就各位。

复算工具:`python tools/name_field_offsets.py <frv_m104_stratagem_dump.txt>`(不需要游戏)。

所以 2.1 起:**先写 package,再写载具;任一个写不进去就一个字节都不写** ——
宁可让你继续开 M-102,也不会给你一辆加载不出资源的车。这一对要么一起成立,要么都不成立。

### 补丁必须跟着关卡走(2.2 的修正,实机又崩了一次"没事但没生效")

2.1 打上之后实机结果是:**不崩了,但下来的还是 M-102**。日志说明补丁确实写进去了
(`patched_copies=1 package_swapped=1`),而且整个会话里 `reapplied=0 foreign=0 dead=0`
—— 也就是说**我们改的那份内存一直完好**,可游戏就是没用它。

原因不在写,在**"只认得飞船上那一份表"**:旧逻辑只有在"所有被改的副本都消失"时才会重新扫描
(`all_targets_dead`),而**释放掉的堆内存并不会把字节清掉** —— 那份陈旧的表会永远读回"是我们的值",
于是 addon 永远以为一切正常。**而一次关卡加载会带来它自己的一整套战备表副本**,任务用的是那一套。

2.2 起:补丁生效期间**每 15 秒查一次地址空间是否变大**(关卡加载的廉价信号),
变大了就**只扫描新增的内存区**(增量扫描,不是把 2.8 GB 重扫一遍 —— 那要好几分钟,
玩家早就把战备叫下来了),找到新的表副本后重新识别并补打。

同时加了一条**"看到了什么"而不是"写了什么"**的观测记录,写进 `FRVM104_STATUS.txt`:

```ini
observed_at_frame=41230
observed_vehicle=ours=2 source=0 other=0 dead=0
observed_package=ours=2 source=0 other=0 dead=0
```

**如果游戏还是给你原车,但这里写着 `ours=2`** —— 那就说明游戏读的根本不是这条记录,
请把状态文件发我(这是区分"写错地方"和"游戏读了别处"的唯一判据)。

**2.2.0 实机结果:喷火车下来了,能开、能喷火。** ✅

不过那一轮的日志显示跟随扫描**还没跑完**(它误把"内存区大小变化"也算成新增,
结果要扫 2293 MB),所以那一次的成功**不能归功于跟随机制** —— 真正让它可靠的正是下面这条修正:

2.2.1 起,**只有"地址是全新的"或"长大了 1 MiB 以上"的内存区才算新增**,
并且增量扫描用更大的每帧预算 —— 真正在"任务侧另有一套表"的情况下抢在玩家叫战备之前补上。

⚠ **实测的诚实数据**:2.2.1 收紧判据后,一次关卡加载带来的新增内存仍然是
**13025 个内存区 / 3176 MB**(这个游戏流式加载的资产就是这么多),所以增量扫描**本身省不了时间** ——
唯一的杠杆是每帧花多少:2.2.2 是 **10 ms/帧**,一次这样的增量大约**半分钟**扫完。
⇒ **实用建议:进任务后等 1 分钟再叫战备**,别等 30 秒。

另外 2.2.2 修了一处**会误导读者的报告**:重扫期间状态首行原来写 `WORKING - scanning`,
看起来像"没生效",其实补丁一直在内存里。现在写的是:

```
OK - patch is STILL applied (1 copy/copies, 1 package(s) swapped,
last seen in place at frame 9364); a level load was noticed and the
13025 new region(s) are being re-scanned ... (N left)
```

### 它不做什么

* **绝不调用 `VirtualProtect`**。数据页本来就是可写的;代码页是只读的,**内核会直接拒绝**这次写 ——
  「绝不改代码段」由操作系统保证,而不是靠这个文件自己判断。实测改 `.text` 会被 GameGuard 当场关游戏。
* 不 spawn 进程、不读别的进程内存、不联网。

## 三、安装

**两条路,选一条:**

**A. 用管理器(推荐,长期)**
1. **如果装过 `M104 FRV Recon`(1.0),先在管理器里把它移除** ——
   两个 addon 的 addon 路径不同,会同时加载(v1 是只读的,不会有害,但会重复扫描并覆盖同名诊断文件)。
2. 用 **HD2 Mod Manager 之类的管理器导入 `M104-FRV-Replacer-2.3.0.zip`**。
3. 启动游戏,在飞船上待几秒。**不用进任务**(战备表在飞船里就在内存里;
   如果不在,addon 会带着退避继续找,并在关卡加载时退还一次扫描预算)。

**B. 手动丢进 `data/`(只为快速验证)**
```powershell
python M104-FRV-Replacer\scripts\deploy.py            # 先看它要写哪个槽位
python M104-FRV-Replacer\scripts\deploy.py --apply    # 写 data\9ba626afa44a3aa3.patch_<最大号+1>
python M104-FRV-Replacer\scripts\deploy.py --uninstall --apply   # 撤销
```
脚本会自己挑当前最大槽位 +1、先验证归档能往返、并打印 loader 上次的发现列表。
**但它只是临时手段**:管理器下次 Deploy 不知道这个文件,长期安装请用 A。

装好后:呼叫 **M-102 Gunner FRV**,下来的是 **M-104 Incinerator FRV**。
战备卡面的名字/图标仍是 M-102(那属于本地化与图标资源,不在这张表里)。

> ⚠️ ZIP 里的 patch 槽位是 `patch_0`,管理器部署时会自己重排编号。用管理器装没问题;
> **手动把 `Addon/` 拷进游戏 `data/` 会和别的 mod 互相覆盖**(症状是「两个一起装总有一个不生效」)。

## 四、看结果:`FRVM104_STATUS.txt` 第一行

文件在 `%LOCALAPPDATA%\CowboyBingus\Helldivers2\Logs\`。

| 第一行 | 含义 | 你要做什么 |
|---|---|---|
| `OK - patch applied: payload field …, (confidence=…), N copy/copies patched` | 成功 | 呼叫 M-102 看看是不是喷火车 |
| `OK - nothing written: …` | 识别没过,**一个字节都没写** | 把 `frv_m104_patch.txt` 发我,证据块里写清了卡在哪一步 |
| `FAILED - …` | 写失败(例如页面只读)或环境不对 | 同上,把 STATUS + patch.txt 发我 |
| `WORKING - …` | 还在扫 | 再等十几秒;或者把文件发我 |
| `DISABLED - …` | 配置里 `enabled = false` | 见下 |

`confidence` 有四种:

| 值 | 含义 |
|---|---|
| `confirmed_by_reference` | M-103 对照记录指向**同一个槽位**(最强) |
| `reference_absent` | 表里找不到 M-103 记录;靠 M-102 id 唯一性下的判断 |
| `field_unverified` | id 在载荷里且唯一,但无法归属到具体记录(扁平扫描兜底) |
| `reference_mismatch` | 对照记录存在但槽位对不上 → **不写**(这一条不允许兜底) |

状态里同时给出本次采用的 `record_stride`(记录步长假设)与 `record_stride` 为空时的原因。

## 五、配置(可选)

mod 首启会在 `%APPDATA%\Arrowhead\Helldivers2\frv_m104.cfg` 写一份带注释的模板,
**已有文件永不覆盖**。

```ini
enabled                = true     ; false = 完全停手(不读不写)
apply                  = true     ; false = 只做识别与取证,绝不写内存
restore_on_shutdown    = true     ; 退出时把原值放回去
require_reference      = false    ; true = 必须由 M-103 双记录确认才写
multi_record           = all      ; all|refuse  多条记录都带 M-102 id 时怎么办
allow_unverified_field = true     ; id 在载荷里但无法归属到记录时,是否照打
patch_package          = true     ; 把 M-104 的资源包哈希一并写进记录 +168
require_package        = true     ; 拿不到资源包就一个字节都不写
```

四类默认值是**故意这样设**的,因为一次会话只有一次机会:

* **`patch_package = true`**:见上面那一节 —— 只换载具不换资源包,游戏会在呼叫战备时空指针崩溃。
  关掉它就退回 2.0 的行为(**已知会崩**),只留给诊断用。
* **`require_package = true`**:找不到 M-104 记录、或它的 `+168` 读不出来时**拒绝写入**,
  宁可你继续开 M-102。这也是**兜底路径**(`field_unverified`)现在会拒绝的原因:
  归属不到记录就没有 `+168` 可读,而缺包的载具正是崩因。想强行只写载具(已知会崩),
  把它设成 `false`。

* **`require_reference = false`**:M-103 的对照记录是**旁证**,不是必要条件。
  一个 64 位**单位哈希**在战备表里独一无二地出现,本身就足够说明问题
  —— 这个 id 出现在这张表里的唯一理由,就是某个战备会生成它。
  所以即使某个构建里找不到 M-103 的记录,补丁照打,并在状态文件里写
  `confidence=reference_absent` 说实话。想要严格版就设成 `true`。
  如果对照记录**存在但对不上**(字段不一致),仍然**拒绝写入**。
* **`multi_record = all`**:若一条实例里有多条记录都带 M-102 的 id
  (例如还有个活动战备也发普通车),**全部都改** —— 这正是「把普通车换成喷火车」的含义。
  设成 `refuse` 就退回「多于一条就拒写」。这条策略在**兜底路径**上同样生效。
* **`allow_unverified_field = true`**:最后一道保险。所有步长假设都没能把 id 归属到某条记录时
  (例如某个构建里记录不是以小枚举开头,`type` 列打不出分),
  只要**扁平扫描证明 id 在载荷里且只出现一次**,就照打,并写 `confidence=field_unverified`。
  理由是:识别靠的是「这个 64 位单位 id 唯一地出现在战备表里」,
  归属到哪条记录只是**交叉验证**;拿不到交叉验证不等于识别错了。
  **注意**:归属不到记录就同样读不到 `+168`,所以默认的 `require_package = true` 会让这条兜底路径
  **拒绝写入**(理由会明写「asset package could not be established」)。
  要让它按老行为只写载具,得同时设 `require_package = false` —— 那是**已知会崩**的组合。

想先只取证再决定?把 `apply` 设成 `false` 重启一次即可 —— 识别流程照跑,
`frv_m104_patch.txt` 里会有完整的判定证据,但一个字节都不写。

## 六、风险与还原

* 改动**只在本机内存**里,禁用 mod + Purge 即可完全还原;`restore_on_shutdown = true` 时退出游戏就还原了。
* 这是**纯数据写入**(堆上的设置结构),不是代码补丁。实测代码补丁会被 nProtect GameGuard 直接关游戏,
  数据写入没有反作弊反应。
* 联机时**别的玩家看不到**你的改动,表现也可能与队友不一致。
* **如果呼叫战备后游戏卡死/窗口消失**:进程可能没退出,而是卡在异常派发自递归里
  (实测:空指针异常 → ntdll 派发自我重入 53 次 → 每 12 秒写一个 141 MB 的 WER 转储、2 核满载、
  栈每秒长 274 字节)。**必须手动结束 `helldivers2.exe`**,否则它会一直转下去,
  转储也会一直往 `%LOCALAPPDATA%\CrashDumps` 里堆(每个 141 MB)。
  顺手把 `apply = false` 设上再复现一次,就能判断到底是补丁还是环境问题。

## 七、诊断产物(失败时发这些)

| 文件 | 内容 |
|---|---|
| `FRVM104_STATUS.txt` | **给玩家看**:第一行结论 + 全部关键参数 |
| `FRVM104.log` | 给开发者看的逐步日志 |
| `frv_m104_patch.txt` | 判定状态、证据链、每个候选 id 的 (副本, 记录, 字段, 地址, 状态) |
| `frv_m104_originals.hex` | 每个被改写 u64 的原始字节(可手工还原) |
| `frv_m104_census.txt` | 内存里**所有** `LDLD` 数据表的地址/类型哈希/大小 |
| `frv_m104_hits.txt` | 4 个 FRV 相关 id 与实体 blob 签名的每次命中 + 归类 |
| `frv_m104_stratagem.txt` | 每份战备表的描述符解码、步长推导、记录命中 |
| `frv_m104_stratagem_dump.txt` | 每份战备表的**完整 hex**(去重) |
| `frv_m104_dump.txt` | 每个命中点 ±1 KB 的 hex |
| `frv_m104_regions.txt` | 扫描过的内存区列表 |

## 八、已排除的备选方案(省得以后重走一遍)

**「不改战备表,改实体表:把普通车的组件索引重指向喷火车那套记录」** —— 已经算过,
**不采用**。原因有两条硬证据:

1. 组件表是**开放寻址哈希表**:`VehicleMotionComponentData` 的载荷是 `26 × 16` 索引 + `13 × 456`
   记录 —— 26 个桶装 13 条记录,也就是**桶位由资源哈希决定**,不是「找个空位塞进去」。
   而喷火车**独有**的组件(`AbilityComponent`、`AttachableComponent`、`BehaviorComponent`、
   `InteractableComponent`)在普通车那一侧**根本没有索引项**,想加就得算准桶位并处理冲突。
2. 就算加成了,**车壳是资源名决定的**:`content/fac_helldivers/vehicles/frv/frv` 这个单位资产
   才是模型来源,重指向组件只会得到「普通车外观 + 喷火器功能」,不是 M-104。

顺带记一条:这次想用社区哈希库给「战备 payload 里的 id」安个名字,
`79e4b3d2da5e45e3` / `75be82ed8592a6b3` / 三个 FRV id **在公开哈希库里一个都查不到**
(`filediver/hashes/hashes.txt`、`work/files.txt`、`work/game_refs.json` 全查过,十六进制与十进制都试了)。
所以「payload[0] = 要生成的单位」这条只能靠**结构验证**(每个值都真的在实体表的组件索引里,
各占 17~37 张表)加上 Exosuit 同族对照来支撑,拿不到「有名字的样本」。

**但是**:把单位名字**反过来算**是能算出来的 —— `content/fac_helldivers/vehicles/frv_heavy/frv_flamer`
的 MurmurHash64A 正好是这个 id。所以「查不到名字」只说明社区名字库没收录,
不说明这个名字不存在;而**验证某辆车到底有没有随包发行**的正确工具是游戏实体数据
(`python tools/check_variant_units.py`:喷火车 39 处引用 vs 对照组 `lav` 0 处)。

## 九、复现(开发者)

```powershell
# 离线身份常量与布局取证(不需要游戏)
python M104-FRV-Replacer\tools\verify_identity.py
python M104-FRV-Replacer\tools\find_frv_hashes.py
python M104-FRV-Replacer\tools\check_payload_convention.py
python M104-FRV-Replacer\tools\stratagem_layout.py
python M104-FRV-Replacer\tools\check_variant_units.py   # 变体的单位数据是否随包发行

# 用真实内存转储复算「社区字段名 -> 实时偏移」的对照表(不需要游戏,也不需要社区表里有 FRV)
python M104-FRV-Replacer\tools\name_field_offsets.py "<转储目录>\frv_m104_stratagem_dump.txt"
python M104-FRV-Replacer\tools\diff_frv_records.py   "<转储目录>\frv_m104_stratagem_dump.txt"

# 离线全套:常量闸门 + 两个 addon 的 LuaJIT 仿真 + 变异测试 + 打包校验
python M104-FRV-Replacer\tests\run_all.py

# 单独跑
python M104-FRV-Replacer\tests\run_tests.py         # 只读侦察 addon,55 项
python M104-FRV-Replacer\tests\run_tests_patch.py   # 补丁 addon,155 项
python M104-FRV-Replacer\tests\run_tests_real.py    # 真实游戏表字节端到端
python M104-FRV-Replacer\tests\run_tests_reconstructed.py  # 真实战备字段值重建整张表
python M104-FRV-Replacer\tests\run_tests_analyzer.py  # 转储分析器独立性
python M104-FRV-Replacer\tests\smoke_patch.py ok    # 跑一个夹具并打印判定

# 拿到失败现场的转储后,独立复算布局(和 addon 不共享任何代码)
python M104-FRV-Replacer\tools\analyze_dump.py "%LOCALAPPDATA%\CowboyBingus\Helldivers2\Logs"

# 崩溃转储(空指针 + ntdll 自递归那次的分析脚本)
python M104-FRV-Replacer\tools\minidump_crash.py "<某个 .dmp>"

# 打包
python M104-FRV-Replacer\scripts\build.py --all
```

离线测试用的是**游戏同款运行时**(`lupa.luajit21`),不是 lupa 默认的 Lua 5.5 ——
否则 `1 << 20` 和 `//` 这种 Lua 5.3+ 语法会一路穿到实机才炸
(本项目的两个真实 bug 就是这么在离线阶段被抓到的)。
