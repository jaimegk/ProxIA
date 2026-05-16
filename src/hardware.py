"""
Hardware detection and Ollama model recommendation.

Called at proxy startup to suggest the most appropriate model based on
available RAM / CPU / GPU, and print a one-time advisory banner.
"""
import platform
import shutil
import subprocess
from dataclasses import dataclass


# Ordered from lightest to heaviest.
# Each entry: (model_id, min_ram_gb, primary, description)
# primary=True → eligible for auto-suggestion; False → listed as alternatives only.
MODEL_CATALOG: list[tuple[str, int, bool, str]] = [
    ("qwen3:0.6b",  2,  True,  "ultra-light  ~0.4 GB · fastest on any CPU"),
    ("qwen3:1.7b",  4,  True,  "default      ~1.1 GB · best speed/quality balance"),
    ("qwen3:4b",    8,  True,  "better       ~2.5 GB · noticeably better accuracy"),
    ("qwen3:8b",   16,  True,  "high-quality ~5.0 GB · slow on CPU-only"),
    ("phi3:mini",   6,  False, "alternative  ~2.2 GB · Microsoft Phi-3"),
    ("llama3.2:3b", 6,  False, "alternative  ~2.0 GB · Meta Llama 3.2"),
]

DEFAULT_MODEL = "qwen3:1.7b"


@dataclass
class HardwareInfo:
    ram_gb: float
    cpu_cores: int
    gpu_vram_gb: float          # 0.0 if no NVIDIA / Apple GPU detected
    is_apple_silicon: bool
    platform_name: str          # "Linux", "Darwin", "Windows"


def _ram_gb_linux() -> float:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / 1024 / 1024, 1)
    except Exception:
        pass
    return 0.0


def _ram_gb_macos() -> float:
    try:
        out = subprocess.check_output(
            ["sysctl", "-n", "hw.memsize"], timeout=2, text=True
        )
        return round(int(out.strip()) / 1024 / 1024 / 1024, 1)
    except Exception:
        pass
    return 0.0


def _cpu_cores() -> int:
    try:
        import os
        return os.cpu_count() or 1
    except Exception:
        return 1


def _nvidia_vram_gb() -> float:
    if not shutil.which("nvidia-smi"):
        return 0.0
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.total",
             "--format=csv,noheader,nounits"],
            timeout=4, text=True, stderr=subprocess.DEVNULL,
        )
        mib = sum(int(x.strip()) for x in out.strip().splitlines() if x.strip().isdigit())
        return round(mib / 1024, 1)
    except Exception:
        return 0.0


def _is_apple_silicon() -> bool:
    try:
        out = subprocess.check_output(
            ["sysctl", "-n", "hw.optional.arm64"], timeout=2,
            text=True, stderr=subprocess.DEVNULL,
        )
        return out.strip() == "1"
    except Exception:
        return False


def detect_hardware() -> HardwareInfo:
    sys_platform = platform.system()

    ram_gb = _ram_gb_linux() if sys_platform == "Linux" else _ram_gb_macos()
    cpu_cores = _cpu_cores()
    gpu_vram = _nvidia_vram_gb()
    apple_si = sys_platform == "Darwin" and _is_apple_silicon()

    # Apple Silicon uses unified memory — treat it as partially GPU-accelerated
    # and count a fraction of system RAM as effective "VRAM" for model sizing.
    effective_vram = gpu_vram if gpu_vram > 0 else (ram_gb * 0.6 if apple_si else 0.0)

    return HardwareInfo(
        ram_gb=ram_gb,
        cpu_cores=cpu_cores,
        gpu_vram_gb=effective_vram,
        is_apple_silicon=apple_si,
        platform_name=sys_platform,
    )


def suggest_model(hw: HardwareInfo) -> str:
    """
    Return the heaviest PRIMARY model that fits within detected hardware.
    GPU/Apple Silicon allows running a tier above CPU-only RAM limits.
    CPU-only machines are capped at qwen3:1.7b — RAM is not the bottleneck there,
    inference speed is (qwen3:4b+ causes timeouts on typical VPS CPUs).
    """
    usable_ram = hw.ram_gb
    cpu_only = hw.gpu_vram_gb == 0 and not hw.is_apple_silicon

    if cpu_only:
        # On CPU-only hosts, cap at 4 GB effective RAM to prevent suggesting
        # models too large for real-time inference (qwen3:4b @ 8 vCPU ≈ 50 t/s → timeouts)
        usable_ram = min(usable_ram, 4)
    else:
        # GPU/Apple-Si lets us run heavier models relative to RAM.
        if hw.gpu_vram_gb >= 8:
            usable_ram = max(usable_ram, 24)   # e.g. NVIDIA 4080 → qwen3:8b
        elif hw.gpu_vram_gb >= 4:
            usable_ram = max(usable_ram, 12)   # e.g. Apple Silicon 8 GB → qwen3:4b
        elif hw.gpu_vram_gb >= 2:
            usable_ram = max(usable_ram, 8)    # e.g. small GPU or Apple 6 GB → qwen3:4b

    best = DEFAULT_MODEL
    for model_id, min_ram, is_primary, _ in MODEL_CATALOG:
        if is_primary and usable_ram >= min_ram:
            best = model_id
    return best


def format_banner(hw: HardwareInfo, suggested: str, active: str) -> list[str]:
    """Return banner lines (no ANSI colors — safe for logs and Docker)."""
    lines: list[str] = []

    gpu_info = ""
    if hw.is_apple_silicon:
        gpu_info = " · Apple Silicon (Metal)"
    elif hw.gpu_vram_gb > 0:
        gpu_info = f" · NVIDIA GPU {hw.gpu_vram_gb:.0f} GB VRAM"

    lines.append("┌─ Hardware auto-detection ─────────────────────────────────────────┐")
    lines.append(f"│  Platform : {hw.platform_name} · {hw.cpu_cores} cores · {hw.ram_gb} GB RAM{gpu_info}")
    lines.append(f"│  Suggested: {suggested}")

    if active != suggested:
        lines.append(f"│  Active   : {active}  ← overridden via OLLAMA_MODEL")
    else:
        lines.append(f"│  Active   : {active}  ← auto-selected (set OLLAMA_MODEL to override)")

    lines.append("│")
    lines.append("│  Available models (set OLLAMA_MODEL=<id>):")
    for model_id, min_ram, _primary, desc in MODEL_CATALOG:
        marker = "▶" if model_id == active else " "
        lines.append(f"│  {marker} {model_id:<20} {desc}  (min {min_ram} GB RAM)")
    lines.append("└───────────────────────────────────────────────────────────────────┘")

    return lines
