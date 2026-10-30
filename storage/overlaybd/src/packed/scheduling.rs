//! Foreground filesystem work must retain a suitable QoS after leaving the
//! calling FSKit queue. The punch worker keeps its default scheduling.
#[cfg(target_os = "macos")]
pub(super) fn current() -> u32 {
    unsafe {
        let mut class: libc::qos_class_t = std::mem::zeroed();
        if libc::pthread_get_qos_class_np(libc::pthread_self(), &mut class, std::ptr::null_mut())
            == 0
        {
            class as u32
        } else {
            0
        }
    }
}
#[cfg(not(target_os = "macos"))]
pub(super) fn current() -> u32 {
    0
}

pub(super) fn foreground() {
    #[cfg(target_os = "macos")]
    unsafe {
        // These bounded workers satisfy active user I/O and flush fences. They
        // sleep on their queues when idle; this is not an interactive/UI class.
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
    }
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn foreground_worker_uses_user_initiated_qos() {
    let qos = std::thread::spawn(|| {
        foreground();
        current()
    })
    .join()
    .unwrap();
    assert_eq!(qos, libc::qos_class_t::QOS_CLASS_USER_INITIATED as u32);
}
