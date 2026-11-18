# xelis-v3-miner

Pure C99 + NVIDIA CUDA **XelisHash V3** GPU miner, standalone legal Hash/Nonce generator (`xelis-v3-hashgen`), and C oracle library (`xelis_v3_oracle`) with **0% dev fee**.

## Highlights

- **4-Thread Sub-Warp Cooperative Architecture**: 4 CUDA threads collaborate per XelisHash V3 instance (`Grid=368x64` default under `2.98 GiB` VRAM), eliminating duplicate Stage 1/Stage 4 ALU work and warp-divergence deadlocks on Blackwell (`sm_120`) Independent Thread Scheduling.
- **Zero PTX Register Spills**: Verified `0 bytes stack frame, 0 bytes spill stores, 0 bytes spill loads` across `sm_75`, `sm_80`, `sm_86`, `sm_89`, `sm_90a`, `sm_100a`, and `sm_120a` (CUDA 13.4.92).
- **Verified Live Performance**: `10,130+ H/s` steady (`10,156 H/s` peak) at `2.98 GiB` VRAM and `103 W` / `60°C` on an NVIDIA GeForce RTX 5070 Ti Laptop GPU (`sm_120`, 46 SMs, 672 GB/s GDDR7), with `0` rejected shares.
- **Dual Protocol Support**:
  1. **Stratum++ TCP / SSL** (`stratum++tcp://`, `stratum++ssl://`, `stratum+tcp://`, `stratum+ssl://`) with OpenSSL TLS + SNI.
  2. **Xelis-V3 Native GetWork** (`ws://`, `wss://`) for `xelis_daemon` (`/getwork/<address>/<worker>`).
- **Pool Alias Support**: Built-in `--pool-mode unmineable` (`COIN:ADDRESS.WORKER#REFERRAL`) and `--pool-mode f2pool` (`ALIAS.WORKER`).
- **Standalone Hash/Nonce Oracle (`xelis-v3-hashgen` & `xelis_v3_oracle.h`)**: C99 API + CLI for deterministic hash calculation (`--hash`), difficulty-meeting nonce/block-branch generation (`--generate --diff <n> --json`), and live pool/daemon submission.

## Supported Architectures

- `sm_60` (Pascal, CUDA 12.x)
- `sm_75` (Turing)
- `sm_80` / `sm_86` (RTX 30 Series Ampere)
- `sm_89` (RTX 40 Series Ada Lovelace)
- `sm_90a` (Hopper)
- `sm_100a` / `sm_120a` (RTX 50 Series Blackwell)

## Build

### Windows (Visual Studio 2022/2026 + CUDA Toolkit + OpenSSL)
```bat
build_windows.bat
```
Outputs: `build\Release\xelis-v3-miner.exe`, `build\Release\xelis-v3-hashgen.exe`, `build\Release\xelis_v3_oracle.lib`.

### Linux (CUDA + OpenSSL)
```bash
make cuda
```
CPU reference & protocol integration test suite (no GPU required):
```bash
make test
```

## Usage

### Stratum++ SSL Pool
```bash
xelis-v3-miner -o stratum++ssl://hk.xelis.herominers.com:1225 --pool-mode standard -u xel:YOUR_ADDRESS -w rig01
```

### unMineable / F2Pool Alias
```bash
xelis-v3-miner -o stratum++ssl://xelishash.unmineable.com:443 --pool-mode unmineable --coin XEL -u xel:YOUR_ADDRESS -w rig01 --referral YOUR_REF
xelis-v3-miner -o stratum++tcp://xel.f2pool.com:3333 --pool-mode f2pool --alias YOUR_ALIAS -w rig01
```

### Xelis-V3 Native Daemon (`ws://`)
```bash
xelis-v3-miner -o ws://127.0.0.1:8080 -u xel:YOUR_ADDRESS -w local_gpu
```

### Standalone Hash/Nonce Generator (`xelis-v3-hashgen`)
```bash
xelis-v3-hashgen --selftest
xelis-v3-hashgen --generate --diff 32 --count 3 --json
xelis-v3-hashgen --hash --work <224_HEX_MINER_WORK> --nonce 21 --json
```

## License

MIT License — see [LICENSE](LICENSE).
