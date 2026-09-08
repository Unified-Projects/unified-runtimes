//! Working out which container the executor is itself running in.
//!
//! The executor has to know its own container so it can attach itself to the
//! runtime networks and so shutdown cleanup does not remove itself. Asking
//! Docker for containers whose name matches the executor's hostname is not
//! enough: runtimes are named `<hostname>-<runtime id>`, so an executor called
//! `exc1` matches every runtime it has ever created, and the first match is
//! usually one of them.
//!
//! On Linux the container ID is readable from `/proc/self/cgroup` or
//! `/proc/self/mountinfo`, which is exact. Everywhere else, and when those
//! files carry no ID (a cgroup namespace hides it), the name filter is used as
//! a fallback with managed runtimes excluded and an exact name preferred.

// Only a Linux host has a proc filesystem to read the ID from. The parsers are
// compiled everywhere regardless, so their tests run on every host.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::container::ContainerInfo;

/// Length of a Docker container ID in hexadecimal characters.
const CONTAINER_ID_LEN: usize = 64;

/// Prefixes container runtimes put in front of the ID in a cgroup path.
const ID_PREFIXES: [&str; 5] = [
    "docker-",
    "crio-",
    "cri-containerd-",
    "libpod-",
    "containerd-",
];

fn is_container_id(candidate: &str) -> bool {
    candidate.len() == CONTAINER_ID_LEN && candidate.chars().all(|c| c.is_ascii_hexdigit())
}

/// Reduce one cgroup path segment to a container ID, if it is one.
fn container_id_from_segment(segment: &str) -> Option<String> {
    let trimmed = segment.strip_suffix(".scope").unwrap_or(segment);
    let trimmed = ID_PREFIXES
        .iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix))
        .unwrap_or(trimmed);

    is_container_id(trimmed).then(|| trimmed.to_string())
}

/// Read the container ID out of `/proc/self/cgroup`.
///
/// Handles the cgroup v1 (`12:pids:/docker/<id>`), cgroup v2
/// (`0::/docker/<id>`) and systemd (`0::/system.slice/docker-<id>.scope`)
/// layouts, plus the Kubernetes paths that embed the ID in the last segment.
/// Returns `None` under a cgroup namespace, where the path is just `/`.
pub fn container_id_from_cgroup(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let path = line.rsplit(':').next().unwrap_or(line);
        for segment in path.split('/').rev() {
            if let Some(id) = container_id_from_segment(segment) {
                return Some(id);
            }
        }
    }

    None
}

/// Read the container ID out of `/proc/self/mountinfo`.
///
/// Docker bind-mounts `/etc/hostname`, `/etc/resolv.conf` and `/etc/hosts`
/// from `.../containers/<id>/` on the host, and the source path survives in
/// mountinfo even when the cgroup path does not carry the ID.
pub fn container_id_from_mountinfo(contents: &str) -> Option<String> {
    for line in contents.lines() {
        for field in line.split_whitespace() {
            let mut segments = field.split('/').peekable();
            while let Some(segment) = segments.next() {
                if segment != "containers" {
                    continue;
                }
                if let Some(candidate) = segments.peek() {
                    if is_container_id(candidate) {
                        return Some((*candidate).to_string());
                    }
                }
            }
        }
    }

    None
}

/// Read the executor's own container ID from the proc filesystem.
#[cfg(target_os = "linux")]
pub async fn own_container_id() -> Option<String> {
    if let Ok(contents) = tokio::fs::read_to_string("/proc/self/cgroup").await {
        if let Some(id) = container_id_from_cgroup(&contents) {
            return Some(id);
        }
    }

    let contents = tokio::fs::read_to_string("/proc/self/mountinfo")
        .await
        .ok()?;
    container_id_from_mountinfo(&contents)
}

#[cfg(not(target_os = "linux"))]
pub async fn own_container_id() -> Option<String> {
    None
}

/// Pick the executor's own container out of a hostname name-filter result.
///
/// The Docker name filter matches substrings, so runtimes created by this
/// executor are in the list too. They are excluded by their `urt.managed`
/// label, and a container whose name is exactly the hostname wins over a
/// longer one. When the choice is still ambiguous nothing is returned, because
/// attaching the wrong container to the runtime networks is worse than not
/// attaching at all.
pub fn select_own_container<'a>(
    candidates: &'a [ContainerInfo],
    hostname: &str,
) -> Option<&'a ContainerInfo> {
    let unmanaged: Vec<&ContainerInfo> = candidates
        .iter()
        .filter(|container| {
            !container
                .labels
                .get("urt.managed")
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        })
        .collect();

    if let Some(exact) = unmanaged
        .iter()
        .find(|container| container.name == hostname)
    {
        return Some(exact);
    }

    match unmanaged.as_slice() {
        [only] => Some(only),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ID: &str = "8d7f1a2b3c4d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7";

    fn container(name: &str, managed: bool) -> ContainerInfo {
        let mut labels = HashMap::new();
        if managed {
            labels.insert("urt.managed".to_string(), "true".to_string());
        }

        ContainerInfo {
            id: "id".to_string(),
            name: name.to_string(),
            image: "image".to_string(),
            state: "running".to_string(),
            status: "Up 1 second".to_string(),
            created: 0,
            labels,
            env: HashMap::new(),
            hostname: String::new(),
        }
    }

    #[test]
    fn cgroup_v1_paths_yield_the_container_id() {
        let contents = format!("12:pids:/docker/{ID}\n11:memory:/docker/{ID}\n");
        assert_eq!(container_id_from_cgroup(&contents), Some(ID.to_string()));
    }

    #[test]
    fn cgroup_v2_and_systemd_scopes_yield_the_container_id() {
        assert_eq!(
            container_id_from_cgroup(&format!("0::/docker/{ID}\n")),
            Some(ID.to_string())
        );
        assert_eq!(
            container_id_from_cgroup(&format!("0::/system.slice/docker-{ID}.scope\n")),
            Some(ID.to_string())
        );
        assert_eq!(
            container_id_from_cgroup(&format!(
                "0::/kubepods/besteffort/pod1234/cri-containerd-{ID}.scope\n"
            )),
            Some(ID.to_string())
        );
    }

    #[test]
    fn a_namespaced_cgroup_carries_no_id() {
        assert_eq!(container_id_from_cgroup("0::/\n"), None);
        assert_eq!(container_id_from_cgroup("12:pids:/user.slice\n"), None);
    }

    #[test]
    fn mountinfo_yields_the_container_id_when_the_cgroup_does_not() {
        let contents = format!(
            "1234 1200 8:1 /var/lib/docker/containers/{ID}/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/sda1 rw\n"
        );
        assert_eq!(container_id_from_mountinfo(&contents), Some(ID.to_string()));
    }

    #[test]
    fn mountinfo_without_a_container_source_yields_nothing() {
        let contents = "26 24 0:22 / /proc rw,nosuid - proc proc rw\n";
        assert_eq!(container_id_from_mountinfo(contents), None);
    }

    #[test]
    fn a_runtime_named_after_the_executor_is_not_mistaken_for_it() {
        let candidates = vec![container("exc1-fn-1", true), container("exc1", false)];
        assert_eq!(
            select_own_container(&candidates, "exc1").map(|c| c.name.as_str()),
            Some("exc1")
        );
    }

    #[test]
    fn only_runtimes_match_means_no_own_container() {
        let candidates = vec![container("exc1-fn-1", true), container("exc1-fn-2", true)];
        assert!(select_own_container(&candidates, "exc1").is_none());
    }

    #[test]
    fn a_single_differently_named_container_is_accepted() {
        let candidates = vec![
            container("openruntimes-executor", false),
            container("exc1-fn-1", true),
        ];
        assert_eq!(
            select_own_container(&candidates, "exc1").map(|c| c.name.as_str()),
            Some("openruntimes-executor")
        );
    }

    #[test]
    fn an_ambiguous_match_is_refused() {
        let candidates = vec![
            container("exc1-proxy", false),
            container("exc1-sidecar", false),
        ];
        assert!(select_own_container(&candidates, "exc1").is_none());
    }
}
