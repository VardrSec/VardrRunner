# Persistent control failure and idle disconnect holds

The refresh failure envelope now includes the local stop-journal precheck. A
transient read failure permanently denies v3 reuse even if a later valid refresh
renews the current finite job and its exact thread joins cleanly.

Native v3 starts one immutable five-second BOOTTIME cleanup deadline after clean
idle-channel EOF. Repeated EOF never extends it; no later frame revives the
channel. Only the exact child's clean waitpid exit establishes success. Healthy
persistent idle has no new timeout; finite v1/v2 and active EOF refusal retain
their behavior. Pure scalar/thread tests are separate from physical disconnect
and containment acceptance.
