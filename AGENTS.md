# AGENTS.md

本仓库是 Salvo 的 Cloudflare Worker 适配分支。协作时优先保持改动贴近 `main` 分支，只为 Worker 编译和运行做必要改造。

## 启动阅读顺序

1. 先读 `.codex/CODE_STYLE.md`。
2. 按任务继续读 `.codex/code-style/` 下的主题文件，Rust/Worker 改动至少读：
   - `00-sampling-and-scope.md`
   - `01-core-principles.md`
   - `02-formatting-and-tooling.md`
   - `03-naming-and-structure.md`
   - `04-rust.md`
   - `06-worker-and-database.md`
   - `07-implementation-workflows.md`
   - `08-git-and-review.md`
3. 再读当前模块的 `Cargo.toml`、相邻 `README.md` 和已有同类实现。

如果这些规则和当前仓库现状冲突，当前仓库已有风格优先；`salvo-worker` 是 fork/upstream 风格很重的仓库，不要为了套个人风格重写大量 upstream 代码。

## 仓库结构

- `crates/*`: Salvo workspace crates。这里大多应贴近 upstream，改动要小且有明确 Worker 兼容理由。
- `salvo-worker/`: Worker 适配 crate，负责把 Cloudflare `worker` runtime request/response 接到 Salvo。
- `worker-examples/`: Worker 示例 workspace，包含实际 wasm32/worker-build 验证入口。
- `examples/`: 普通 Salvo 示例，除非任务明确涉及，不要顺手整理。

## 工作区和 Git 边界

- 开工先看 `git status --short --branch`。
- 暂存区是用户维护的提交边界。除非用户明确要求，不要执行 `git add`、`git restore --staged`、`git reset` 或会改变 index 的命令。
- 已 staged 的文件只查看，不要为了整理 diff 把它们移回 unstaged。
- 新增或修改代码默认保持 unstaged，并在交付时说明哪些文件是本次改动。
- 不要回退用户已有改动；如果同一文件里有用户改动，先读清楚再叠加最小修改。

## Rust 风格

- 使用 Rust 2024 workspace 约定，保留现有 lint，不要为了快速通过检查删除 lint。
- 公共 API 和 crate 文档优先保持稳定；`lib.rs`、runtime entry 和 adapter 入口保持薄。
- 业务或平台错误返回 `Result`，不要用 `unwrap`、`expect`、`panic` 处理用户输入、网络、Worker runtime、数据库或远程调用错误。
- 命名可以长，但要表达对象和动作；模块、函数、变量使用 `snake_case`，类型和 trait 使用 `PascalCase`。
- 新抽象只在能减少真实复杂度、重复或明确匹配本地模式时增加。
- 注释只解释平台限制、兼容原因、跨层映射、锁/回滚/运行时坑点，避免复述代码。

## Worker 兼容原则

- Worker 分支的目标是能在 `wasm32-unknown-unknown` 和 Cloudflare Worker runtime 下编译运行。
- 适配层不要提前 buffer 请求或响应 body。涉及 request/response bridge、proxy、SSE、stream、upload/download 时，优先保留流式 body 和 backpressure。
- 避免引入依赖 Worker wasm runtime 不支持的能力，例如裸 tokio I/O、文件系统、native TLS、ring 相关默认能力等。
- 新增或调整 feature gate 时保持默认能力保守，说明开启后引入的依赖和 Worker 兼容影响。
- `worker-examples` 当前用于验证实际 Worker 构建路径；其中 `worker` / `worker-macros` / `worker-build` 版本约束不要在无明确要求时升级。
- `reqwest` 的 `stream` 能力对流式转发有意义，不要为了绕过构建问题随意移除。

## 常用验证命令

根 workspace 常用：

```bash
cargo fmt
cargo clippy
```

Worker 示例 wasm release build：

```bash
cd worker-examples/template
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' WASM_BINDGEN_USE_JS_SYS=1 cargo build --lib --release --target wasm32-unknown-unknown
```

Worker 示例 wasm clippy：

```bash
cd worker-examples
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' WASM_BINDGEN_USE_JS_SYS=1 cargo clippy --target wasm32-unknown-unknown
```

如果只改文档，可以不跑完整 Rust 检查，但要说明未运行原因。涉及 Worker 编译、依赖、stream、request/response bridge 时，至少跑 host `cargo clippy` 和 wasm build。

## 改动策略

- 先判断改动是 upstream 通用修复，还是 Worker-only 兼容层。Worker-only 逻辑优先收敛到 `salvo-worker/`、feature gate 或明确的 `cfg(target_family = "wasm")` 边界。
- 贴近 `main` 分支，避免大范围重排、命名统一、格式化全仓库或无关重构。
- 依赖升级单独处理；升级后检查 lockfile 是否有大面积无关漂移。
- 对 `time`、`worker`、`wasm-streams`、`reqwest`、`cookie` 这类 Worker 编译敏感依赖，先验证 wasm target，再判断是否接受升级。
- 修复 bug 时优先保留原 API 和原行为；新增逻辑应尽量作为窄 wrapper 或 adapter，不扩大调用方契约。

## Review 口径

- review 时先区分 staged 和 unstaged，再说明检查边界。
- 优先找行为 bug、数据截断、streaming 退化、Worker runtime 不兼容、feature gate 误伤、依赖解析漂移和测试缺口。
- 结论要带文件和行号；没有发现阻塞问题时也要说明还没跑哪些检查。
- 对 Cloudflare Worker 相关代码，不要只看 host 编译结果；host 通过不代表 wasm runtime 可用。
