//! Automatic computation of `max_connections` from system resources.

use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxConnections {
    Auto,
    Fixed(usize),
}

impl FromStr for MaxConnections {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let n = s.parse::<usize>().map_err(|_| {
            format!("Invalid max_connections '{s}'. Use 'auto' or a positive integer")
        })?;
        if n == 0 {
            return Err(format!(
                "Invalid max_connections '{s}'. Must be 'auto' or a positive integer (>= 1)"
            ));
        }
        Ok(Self::Fixed(n))
    }
}

const PER_CORE_MBPS: u64 = 1500;
const PER_USER_KBPS: u64 = 200;
const PER_SESSION_KB: u64 = 200;
const MEM_BUDGET_PCT: u64 = 50;
const FD_RESERVE_DEFAULT: u64 = 1024;
const FD_PER_SESSION: u64 = 2;

pub fn compute_auto(cpus: usize, total_mem_kb: u64, nofile_soft: u64) -> AutoBreakdown {
    let cpus = cpus.max(1) as u64;

    let cpu_cap = cpus.saturating_mul(PER_CORE_MBPS).saturating_mul(1000) / PER_USER_KBPS;
    let mem_cap = total_mem_kb.saturating_mul(MEM_BUDGET_PCT) / 100 / PER_SESSION_KB;

    let fd_reserve = FD_RESERVE_DEFAULT.min(nofile_soft / 4);
    let fd_cap = nofile_soft.saturating_sub(fd_reserve) / FD_PER_SESSION;

    let raw = cpu_cap.min(mem_cap).min(fd_cap);
    let value = (raw.max(1)) as usize;

    let limiting = if cpu_cap <= mem_cap && cpu_cap <= fd_cap {
        Limit::Cpu
    } else if mem_cap <= fd_cap {
        Limit::Memory
    } else {
        Limit::FileDescriptors
    };

    AutoBreakdown {
        value,
        cpu_cap,
        mem_cap,
        fd_cap,
        limiting,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Cpu,
    Memory,
    FileDescriptors,
}

impl Limit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Limit::Cpu => "cpu",
            Limit::Memory => "memory",
            Limit::FileDescriptors => "fd",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AutoBreakdown {
    pub value: usize,
    pub cpu_cap: u64,
    pub mem_cap: u64,
    pub fd_cap: u64,
    pub limiting: Limit,
}

pub fn fixed_exceeds_auto_cap(value: usize, bd: &AutoBreakdown) -> bool {
    let v = value as u64;
    v > bd.cpu_cap || v > bd.mem_cap || v > bd.fd_cap
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    Auto,
    Fixed,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedMaxConnections {
    pub value: usize,
    pub mode: ResolveMode,
    pub breakdown: AutoBreakdown,
    pub cpus: usize,
    pub total_mem_kb: u64,
    pub nofile_soft: u64,
}

pub fn resolve(spec: MaxConnections) -> ResolvedMaxConnections {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let total_mem_kb = total_memory_kb().unwrap_or(4 * 1024 * 1024);
    let nofile_soft = nofile_soft_limit().unwrap_or(65_536);

    let breakdown = compute_auto(cpus, total_mem_kb, nofile_soft);

    let (value, mode) = match spec {
        MaxConnections::Fixed(n) => (n, ResolveMode::Fixed),
        MaxConnections::Auto => (breakdown.value, ResolveMode::Auto),
    };

    ResolvedMaxConnections {
        value,
        mode,
        breakdown,
        cpus,
        total_mem_kb,
        nofile_soft,
    }
}

#[cfg(target_os = "linux")]
fn total_memory_kb() -> Option<u64> {
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages > 0 && page_size > 0 {
        Some((pages as u64).saturating_mul(page_size as u64) / 1024)
    } else {
        None
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn total_memory_kb() -> Option<u64> {
    None
}

#[cfg(not(unix))]
fn total_memory_kb() -> Option<u64> {
    None
}

#[cfg(unix)]
fn nofile_soft_limit() -> Option<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if ret == 0 {
        Some(rl.rlim_cur)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn nofile_soft_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gb_to_kb(gb: u64) -> u64 {
        gb * 1024 * 1024
    }

    #[test]
    fn parses_auto_case_insensitive() {
        assert_eq!(
            "auto".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
        assert_eq!(
            "AUTO".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
    }

    #[test]
    fn parses_fixed_integer() {
        assert_eq!(
            "5000".parse::<MaxConnections>().unwrap(),
            MaxConnections::Fixed(5000)
        );
    }

    #[test]
    fn zero_is_rejected() {
        assert!("0".parse::<MaxConnections>().is_err());
    }

    #[test]
    fn resolve_auto_smokes() {
        let r = resolve(MaxConnections::Auto);
        assert_eq!(r.mode, ResolveMode::Auto);
        assert!(r.value >= 1);
    }

    #[test]
    fn degenerate_zero_inputs_floor_to_one() {
        let bd = compute_auto(1, 0, 0);
        assert_eq!(bd.value, 1);
    }

    #[test]
    fn large_cpu_huge_ram_is_cpu_bound() {
        let bd = compute_auto(4, gb_to_kb(16), 65_536);
        assert_eq!(bd.limiting, Limit::Cpu);
        assert_eq!(bd.value, 30_000);
    }
}
